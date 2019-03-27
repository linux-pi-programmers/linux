/* Copyright (C) 2019 WiNG NITK Surathkal
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: Gurupungav Narayanan <gurupungavn@gmail.com>
 * Author: Suraj Singh <suraj1998@gmail.com>
 * Author: Adwaith Gautham <adwait.gautham@gmail.com>
 *
 * References:
 * On designing improved controllers for AQM routers supporting TCP flows
 * DOI: 10.1109/INFCOM.2001.916670
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define QUEUE_THRESHOLD 16384
#define DQCOUNT_INVALID -1
#define MAX_PROB 0xffffffffffffffff
#define PI_SCALE 8
#define PARAMETER_SCALE 100000000

/* parameters used */
struct pi_params {
	u32 target;
	u32 tupdate;		/* timer frequency (in jiffies) */
	u32 limit;		/* number of packets that can be enqueued */
	u32 alpha;		/* alpha and beta are between 0 and 32 */
	u32 beta;		/* and are used for shift relative to 1 */
	bool ecn;		/* true if ecn is enabled */
	bool bytemode;		/* to scale drop early prob based on pkt size */
};

/* variables used */
struct pi_vars {
	u64 prob;		/* probability but scaled by u64 limit. */
	u32 qlen_old;		/* in bytes */
};

/* statistics gathering */
struct pi_stats {
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to pi_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u32 maxq;		/* maximum queue size */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* private data for the Qdisc */
struct pi_sched_data {
	struct pi_params params;
	struct pi_vars vars;
	struct pi_stats stats;
	struct timer_list adapt_timer;
	struct Qdisc *sch;
};

static void pi_params_init(struct pi_params *params)
{
	params->alpha = 1822;
	params->beta = 1816;
	params->tupdate = usecs_to_jiffies(625 * USEC_PER_MSEC / 1000);	/* 6.25 ms */
	params->limit = 1000;	/* default of 1000 packets */
	params->target = 50; /* correct value, but is it packets */
	params->ecn = false;
	params->bytemode = false;
}


static bool drop_early(struct Qdisc *sch, u32 packet_size)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	u64 rnd;
	u64 local_prob = q->vars.prob;
	// Shouldn't we do q->vars.prob = 0 in pi_vars_init() ?
	u32 mtu = psched_mtu(qdisc_dev(sch));

	/* If we have fewer than 2 mtu-sized packets, disable drop_early,
	 * similar to min_th in RED
	 */
	if (sch->qstats.backlog < 2 * mtu)
		return false;

	/* If bytemode is turned on, use packet size to compute new
	 * probablity. Smaller packets will have lower drop prob in this case
	 */
	if (q->params.bytemode && packet_size <= mtu)
		local_prob = (u64)packet_size * div_u64(local_prob, mtu);
	else
		local_prob = q->vars.prob;

	prandom_bytes(&rnd, 8);
	if (rnd < local_prob)
		return true;

	return false;
}

static int pi_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	bool enqueue = false;

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, skb->len)) {
		enqueue = true;
	} else if (q->params.ecn && INET_ECN_set_ce(skb)) {
		/* If packet is ecn capable, mark it */
		q->stats.ecn_mark++;
		enqueue = true;
	}

	/* we can enqueue the packet */
	if (enqueue) {
		q->stats.packets_in++;
		if (qdisc_qlen(sch) > q->stats.maxq)
			q->stats.maxq = qdisc_qlen(sch);

		return qdisc_enqueue_tail(skb, sch);
	}

out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
}

static const struct nla_policy pi_policy[TCA_PI_MAX + 1] = {
	[TCA_PI_TARGET] = {.type = NLA_U32},
	[TCA_PI_LIMIT] = {.type = NLA_U32},
	[TCA_PI_TUPDATE] = {.type = NLA_U32},
	[TCA_PI_ALPHA] = {.type = NLA_U32},
	[TCA_PI_BETA] = {.type = NLA_U32},
	[TCA_PI_ECN] = {.type = NLA_U32},
	[TCA_PI_BYTEMODE] = {.type = NLA_U32},
};

static int pi_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_PI_MAX + 1];
	unsigned int qlen, dropped = 0;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_PI_MAX, opt, pi_policy, NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	/* should be number of packets */
	if (tb[TCA_PI_TARGET])
		q->params.target = nla_get_u32(tb[TCA_PI_TARGET]);

	/* tupdate is in jiffies */
	if (tb[TCA_PI_TUPDATE])
		q->params.tupdate =
			usecs_to_jiffies(nla_get_u32(tb[TCA_PI_TUPDATE]));

	if (tb[TCA_PI_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_PI_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	/* needs to be scaled */
	if (tb[TCA_PI_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_PI_ALPHA]);

	/* needs to be scaled */
	if (tb[TCA_PI_BETA])
		q->params.beta = nla_get_u32(tb[TCA_PI_BETA]);

	if (tb[TCA_PI_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_PI_ECN]);

	if (tb[TCA_PI_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_PI_BYTEMODE]);

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		dropped += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_qdisc_drop(skb, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	sch_tree_unlock(sch);
	return 0;
}

static void calculate_probability(struct Qdisc *sch)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	u32 qlen = qdisc_qlen(sch);	/* queue size in bytes */
	u32 qlen_old = q->vars.qlen_old;
	s64 delta = 0;		/* determines the change in probability */
	u64 oldprob;
	u64 alpha, beta;
	bool update_prob = true;

	q->vars.qlen_old = qlen;

	/* In the algorithm, alpha and beta are between 0 and 2 with typical
	 * value for alpha as 0.125. In this implementation, we use values 0-32
	 * passed from user space to represent this. Also, alpha and beta have
	 * unit of HZ and need to be scaled before they can used to update
	 * probability. alpha/beta are updated locally below by scaling down
	 * by 16 to come to 0-2 range.
	 */
	alpha = ((u64)q->params.alpha * (MAX_PROB)) / PARAMETER_SCALE; 
	beta = ((u64)q->params.beta * (MAX_PROB)) / PARAMETER_SCALE;

	/* alpha and beta should be between 0 and 32, in multiples of 1/16 */
	delta += alpha * (u64)(qlen - q->params.target);
	delta -= beta * (u64)(qlen_old - q->params.target);

	oldprob = q->vars.prob;

	q->vars.prob += delta;

	if (delta > 0) {
		/* prevent overflow */
		if (q->vars.prob < oldprob) {
			q->vars.prob = MAX_PROB;
			/* Prevent normalization error. If probability is at
			 * maximum value already, we normalize it here, and
			 * skip the check to do a non-linear drop in the next
			 * section.
			 */
			update_prob = false;
		}
	} else {
		/* prevent underflow */
		if (q->vars.prob > oldprob)
			q->vars.prob = 0;
	}

	q->vars.qlen_old = qlen;
}

static void pi_timer(struct timer_list *t)
{
	struct pi_sched_data *q = from_timer(q, t, adapt_timer);
	struct Qdisc *sch = q->sch;
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

	spin_lock(root_lock);
	calculate_probability(sch);

	/* reset the timer to fire after 'tupdate'. tupdate is in jiffies. */
	if (q->params.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.tupdate);
	spin_unlock(root_lock);
}

static int pi_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct pi_sched_data *q = qdisc_priv(sch);

	pi_params_init(&q->params);
	sch->limit = q->params.limit;

	q->sch = sch;
	timer_setup(&q->adapt_timer, pi_timer, 0);

	if (opt) {
		int err = pi_change(sch, opt, extack);

		if (err)
			return err;
	}

	mod_timer(&q->adapt_timer, jiffies + HZ / 2);
	return 0;
}

static int pi_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_PI_TARGET, q->params.target) ||
	    nla_put_u32(skb, TCA_PI_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_PI_TUPDATE,
			jiffies_to_usecs(q->params.tupdate)) ||
	    nla_put_u32(skb, TCA_PI_ALPHA, q->params.alpha) ||
	    nla_put_u32(skb, TCA_PI_BETA, q->params.beta) ||
	    nla_put_u32(skb, TCA_PI_ECN, q->params.ecn) ||
	    nla_put_u32(skb, TCA_PI_BYTEMODE, q->params.bytemode))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

static int pi_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	struct tc_pi_xstats st = { // Need to verify if all params are needed
		.prob		= q->vars.prob,
		.packets_in	= q->stats.packets_in,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.dropped	= q->stats.dropped,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *pi_qdisc_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb = qdisc_dequeue_head(sch);

	if (!skb)
		return NULL;

	// pi_process_dequeue(sch, skb);
	return skb;
}

static void pi_reset(struct Qdisc *sch)
{

	qdisc_reset_queue(sch);
}

static void pi_destroy(struct Qdisc *sch)
{
	struct pi_sched_data *q = qdisc_priv(sch);

	q->params.tupdate = 0;
	del_timer_sync(&q->adapt_timer);
}

static struct Qdisc_ops pi_qdisc_ops __read_mostly = {
	.id = "pi",
	.priv_size	= sizeof(struct pi_sched_data),
	.enqueue	= pi_qdisc_enqueue,
	.dequeue	= pi_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= pi_init,
	.destroy	= pi_destroy,
	.reset		= pi_reset,
	.change		= pi_change,
	.dump		= pi_dump,
	.dump_stats	= pi_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init pi_module_init(void)
{
	return register_qdisc(&pi_qdisc_ops);
}

static void __exit pi_module_exit(void)
{
	unregister_qdisc(&pi_qdisc_ops);
}

module_init(pi_module_init);
module_exit(pi_module_exit);

MODULE_DESCRIPTION("Proportional Integral controller (PI) scheduler");
MODULE_AUTHOR("Gurupungav Narayanan");
MODULE_AUTHOR("Adwaith Gautham");
MODULE_AUTHOR("Suraj Singh");
MODULE_LICENSE("GPL");
