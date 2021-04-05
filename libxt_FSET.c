/*
 *	"FSET" target extension for iptables
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
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/xt_set.h>
#include "xt_FSET.h"
#include "compat_libxt_set.h"

static const struct option fset_tg_opts[] = {
	{.name = "add-set",   .has_arg = true,  .val = 'a'},
	{.name = "del-set",   .has_arg = true,  .val = 'd'},
	{.name = "offset",  .has_arg = true,  .val = 'o'},
	{.name = "log",  .has_arg = false, .val = 'l'},
	{NULL},
};

static void fset_tg_help(void)
{
	printf(
"FSET target options:\n"
"  --add-set name    IPSET name to insert record to \n"
"  --del-set name    IPSET name to remove record from \n"
"  --offset offset   Data offset inside the packet (numeric)\n"
"  --log             Write events to syslog\n"
);
}

static void fset_tg_init(struct xt_entry_target *target)
{
	struct xt_fset_tginfo *info = (void *)target->data;

	info->offset   = 0;
	info->flags    = 0;
	info->add_set.index = info->del_set.index = IPSET_INVALID_ID;
}

static void
fset_tg_parse_setname(struct xt_fset_set_info *info)
{
	if (strlen(optarg) > IPSET_MAXNAMELEN - 1) 
	{
		xtables_error(PARAMETER_PROBLEM,
			      "setname `%s' too long, max %d characters.",
			      optarg, IPSET_MAXNAMELEN - 1);
		return;
	}
	get_set_byname(optarg, info);
}

static int
fset_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                 const void *entry, struct xt_entry_target **target)
{
	struct xt_fset_tginfo *info = (void *)(*target)->data;
	unsigned int x;

	if (invert)
		xtables_error(PARAMETER_PROBLEM,"Can't specify ! in FSET target params");

	switch (c) {
	case 'o': /* --offset */
		xtables_param_act(XTF_ONLY_ONCE, "FSET", "--offset", *flags & FSET_TG_F_OFFSET);
		if (!xtables_strtoui(optarg, NULL, &x, 0, 65535))
			xtables_param_act(XTF_BAD_VALUE, "FSET", "--offset", optarg);
		info->offset = x;
		*flags |= FSET_TG_F_OFFSET;
		return true;

	case 'a': /* --add-set */
		xtables_param_act(XTF_ONLY_ONCE, "FSET", "--add-set", *flags & FSET_TG_F_ACTION_ADD);
		fset_tg_parse_setname(&info->add_set);
		*flags |= FSET_TG_F_ACTION_ADD;
		return true;

	case 'd': /* --del-set */
		xtables_param_act(XTF_ONLY_ONCE, "FSET", "--del-set", *flags & FSET_TG_F_ACTION_DEL);
		fset_tg_parse_setname(&info->del_set);
		*flags |= FSET_TG_F_ACTION_DEL;
		return true;

	case 'l': /* --log */
		*flags |= FSET_TG_F_LOG;
		info->flags |= FSET_TG_F_LOG;
		return true;
	}
	return false;
}

static void
fset_tg_check(unsigned int flags)
{
	if (!(flags & (FSET_TG_F_ACTION_ADD|FSET_TG_F_ACTION_DEL)))
		xtables_error(PARAMETER_PROBLEM,
			      "You must specify either `--add-set' or "
			      "`--del-set'");
	if (!(flags & FSET_TG_F_OFFSET))
		xtables_error(PARAMETER_PROBLEM,
			      "You must specify the data offset to grab from the packet");
}


static void
fset_print_tg_action(const char *prefix, const struct xt_fset_set_info *info)
{
	char setname[IPSET_MAXNAMELEN];

	if (info->index == IPSET_INVALID_ID)
		return;
	get_set_byid(setname, info->index);
	printf(" %s %s", prefix, setname);
}

static void
fset_tg_print(const void *ip, const struct xt_entry_target *target,
                 int numeric)
{

	const struct xt_fset_tginfo *info = (void *)target->data;

	printf(" -j FSET");
	fset_print_tg_action("--add-set", &info->add_set);
	fset_print_tg_action("--del-set", &info->del_set);
	printf(" --offset %u", info->offset);
	if (info->flags & FSET_TG_F_LOG)
	    printf(" --log");
}

static void
fset_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_fset_tginfo *info = (void *)target->data;

	fset_print_tg_action("--add-set", &info->add_set);
	fset_print_tg_action("--del-set", &info->del_set);
	printf(" --offset %u", info->offset);
	if (info->flags & FSET_TG_F_LOG)
	    printf(" --log");
}

static struct xtables_target fset_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "FSET",
	.revision      = 0,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_fset_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_fset_tginfo)),
	.help          = fset_tg_help,
	.init          = fset_tg_init,
	.parse         = fset_tg_parse,
	.final_check   = fset_tg_check,
	.print         = fset_tg_print,
	.save          = fset_tg_save,
	.extra_opts    = fset_tg_opts,
};

static __attribute__((constructor)) void fset_tg_ldr(void)
{
	xtables_register_target(&fset_tg_reg);
}
