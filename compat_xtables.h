#ifndef _LINUX_NETFILTER_XT_FSET_COMPAT_XTABLES
#define _LINUX_NETFILTER_XT_FSET_COMPAT_XTABLES 1

struct xtables_afinfo {
	const char *kmod;
	const char *proc_exists;
	const char *libprefix;
	uint8_t family;
	uint8_t ipproto;
	int so_rev_match;
	int so_rev_target;
};

extern const struct xtables_afinfo *afinfo;

#endif /* _LINUX_NETFILTER_XT_FSET_COMPAT_XTABLES */
