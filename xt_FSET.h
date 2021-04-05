#ifndef _LINUX_NETFILTER_XT_FSET_TARGET_H
#define _LINUX_NETFILTER_XT_FSET_TARGET_H 1

#include <linux/netfilter/xt_set.h>

#define FSET_TG_F_ACTION_ADD	0x10
#define FSET_TG_F_ACTION_DEL	0x20
#define FSET_TG_F_OFFSET	0x01
#define FSET_TG_F_LOG		0x02

//ipset description we work with
struct xt_fset_set_info {
	ip_set_id_t index; //ipset id
};

//iptables rule description
struct xt_fset_tginfo {
	u_int16_t offset;
	u_int8_t  flags;
	struct xt_fset_set_info add_set;
	struct xt_fset_set_info del_set;
};

#endif /* _LINUX_NETFILTER_XT_FSET_TARGET_H */


