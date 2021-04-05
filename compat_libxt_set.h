#ifndef _LINUX_NETFILTER_XT_FSET_COMPAT_LIBXT_SET_H
#define _LINUX_NETFILTER_XT_FSET_COMPAT_LIBXT_SET_H 1

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "compat_xtables.h"

/* partial fork of of libxt_set.h iptables sources*/

static int
get_version(unsigned *version)
{
	int res, sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);
	
	if (sockfd < 0)
		xtables_error(OTHER_PROBLEM,
			      "Can't open socket to ipset.\n");

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		xtables_error(OTHER_PROBLEM,
			      "Could not set close on exec: %s\n",
			      strerror(errno));
	}

	req_version.op = IP_SET_OP_VERSION;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req_version, &size);
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			      "Kernel module xt_set is not loaded in.\n");

	*version = req_version.version;
	
	return sockfd;
}


static void
get_set_byname(const char *setname, struct xt_fset_set_info *info)
{
	struct ip_set_req_get_set_family req;
	socklen_t size = sizeof(struct ip_set_req_get_set_family);
	int res, sockfd;

	sockfd = get_version(&req.version);
	req.op = IP_SET_OP_GET_FNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);

	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set_family))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set_family),
			(size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);
	if (!(req.family == afinfo->family ||
	      req.family == NFPROTO_UNSPEC))
		xtables_error(PARAMETER_PROBLEM,
			      "The protocol family of set %s is %s, "
			      "which is not applicable.\n",
			      setname,
			      req.family == NFPROTO_IPV4 ? "IPv4" : "IPv6");

	info->index = req.set.index;
}

static void
get_set_byid(char *setname, ip_set_id_t idx)
{
	struct ip_set_req_get_set req;
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res, sockfd;

	sockfd = get_version(&req.version);
	req.op = IP_SET_OP_GET_BYINDEX;
	req.set.index = idx;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.name[0] == '\0')
		xtables_error(PARAMETER_PROBLEM,
			"Set with index %i in kernel doesn't exist.\n", idx);

	strncpy(setname, req.set.name, IPSET_MAXNAMELEN);
}

#endif /* _LINUX_NETFILTER_XT_FSET_COMPAT_LIBXT_SET_H */


