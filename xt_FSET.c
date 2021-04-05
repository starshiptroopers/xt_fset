/*
 *	"FSET" target extension to Xtables (iptables)
 *	Manipulates kernel IPSET (add or delete elements) with IP address grabbed from customizable offset in network packet
 *	Can use to remotelly add or remove IP address to/from ipset
 *
 *	Copyright 2021 The Starship Troopers, Cherviakov Aleksandr. All rights reserved.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include "xt_FSET.h"
#include <linux/ip.h>

static unsigned int
fset_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	__be32 addr;

	const struct xt_fset_tginfo *info = par->targinfo;
	const unsigned int offset = (unsigned int) info->offset;
	struct iphdr *newiphdr;     //new skbbuff ip header
	struct sk_buff *newskb;
	const struct iphdr *iphdr;  //current packet skbuff ip header

	/* ip_set kernel API command options */
	struct ip_set_adt_opt ipset_cmd_opt = {
		.family	= xt_family(par),   //proto family
		.dim = 1,                   //size of data fields stored in ip set (always 1 for simple hash:ip ipset)
		.flags = IPSET_DIM_ONE_SRC, //which ip address (SRC or DST) we put into ipset
		.cmdflags = 0,              //internall struct
		.ext.timeout = UINT_MAX     //we don't operate which timeout feature now, fill it with max value
	};

	if (offset > skb->len - sizeof(addr))
	    return XT_CONTINUE;

	if (skb_copy_bits(skb, offset, &addr, sizeof(addr)) < 0)
	    BUG();

	//to print this debug output build the file with -DDEBUG flag by adding CFLAGS_[filename].o := -DDEBUG to makefile
	pr_debug(" We'v got a packet with protocol=0x%x and data at offset %i: 0x%x\n", ip_hdr(skb)->protocol, offset, addr);

	/*  ipset kernel api functions operate with skb structure only, and we can't put the IP directly.
	    we need to create new network skb struct, fill the srcip field of ip header and put them to ipset API
	*/

	newskb = alloc_skb(LL_MAX_HEADER + sizeof(*newiphdr), GFP_ATOMIC);

	if (newskb == NULL)
		return NF_DROP;
	skb_reserve(newskb, LL_MAX_HEADER);
	newskb->protocol = skb->protocol;
	skb_reset_network_header(newskb);
	iphdr  = ip_hdr(skb);
	newiphdr = (void *)skb_put(newskb, sizeof(*newiphdr));
	*newiphdr = *iphdr;
	newiphdr->saddr = addr;

	if (info->add_set.index != IPSET_INVALID_ID) {
		if (!ip_set_add(info->add_set.index, newskb, par, &ipset_cmd_opt) &&
		    info->flags & FSET_TG_F_LOG)
			printk("FSET: %pI4 has been added to ipset\n", &addr);
	}
	if (info->del_set.index != IPSET_INVALID_ID) {
		if (!ip_set_del(info->del_set.index, newskb, par, &ipset_cmd_opt) &&
		    info->flags & FSET_TG_F_LOG)
			printk("FSET: %pI4 has been removed from ipset\n", &addr);
	}

	kfree_skb(newskb);
	return XT_CONTINUE;
}

static int
fset_tg_checkentry(const struct xt_tgchk_param *par)
{
	const struct xt_fset_tginfo *info = par->targinfo;
	ip_set_id_t index;

	if (info->add_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(par->net, info->add_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_warn("Cannot find add_set index %u as target\n", info->add_set.index);
			return -ENOENT;
		}
	}

	if (info->del_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(par->net, info->del_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_warn("Cannot find del_set index %u as target\n", info->del_set.index);
			/* remove possible garbage ip_set link ? */
			if (info->add_set.index != IPSET_INVALID_ID)
				ip_set_nfnl_put(par->net, info->add_set.index);
			return -ENOENT;
		}
	}

	return 0;
}

static void
fset_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_fset_tginfo *info = par->targinfo;

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->add_set.index);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->del_set.index);
}

static struct xt_target fset_tg_reg[] __read_mostly = {
	{
		.name       = "FSET",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = fset_tg,
		.checkentry = fset_tg_checkentry,
		.destroy    = fset_tg_destroy,
		.targetsize = sizeof(struct xt_fset_tginfo),
		.me         = THIS_MODULE,
	},
/*
// not implemented yet
	{
		.name       = "FSET",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = fset_tg,
		.targetsize = sizeof(struct xt_fset_tginfo),
		.me         = THIS_MODULE,
	},
*/
};

static int __init fset_tg_init(void)
{
	return xt_register_targets(fset_tg_reg, ARRAY_SIZE(fset_tg_reg));
}

static void __exit fset_tg_exit(void)
{
	xt_unregister_targets(fset_tg_reg, ARRAY_SIZE(fset_tg_reg));
}

module_init(fset_tg_init);
module_exit(fset_tg_exit);
MODULE_DESCRIPTION("Xtables: ipset target extension which fill the set with any packet data");
MODULE_AUTHOR("Aleksandr Cherviakov");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_FSET");
//MODULE_ALIAS("ip6t_FSET");
