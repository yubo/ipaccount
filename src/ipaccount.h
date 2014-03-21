/*
 *   Author:      yubo <yubo@xiaomi.com> 
 *                This program is free software; you can redistribute it and/or
 *                modify it under the terms of the GNU General Public License
 *                as published by the Free Software Foundation; either version
 *                2 of the License, or (at your option) any later version.
 **/


#ifndef __IPACCOUNT_H
#define __IPACCOUNT_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/types.h>	/* For __beXX types in userland */


#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "ip_account.h"

#define LIB_IPACCOUNT_VERSION "0.1"

/* Don't set this below the size of struct ip_account_handle_sockopt */
#define IP_ACCOUNT_MIN_BUFSIZE 4096




int ip_acc_init(void);
void ip_acc_deinit(void);
struct ip_acc_get_tables *ipacc_get_tables(void);
int ipacc_add_table(struct ip_acc_table_user_kern *itb);
int ipacc_set_table(struct ip_acc_table_user_kern *itb);
int ipacc_del_table(struct ip_acc_table_user_kern *itb);

struct ip_acc_get_ips *ipacc_get_ips(struct ip_acc_table_user_kern *itb);







extern struct nla_policy ipacc_cmd_policy[IPACC_CMD_ATTR_MAX + 1];
extern struct nla_policy ipacc_table_policy[IPACC_TABLE_ATTR_MAX + 1];
extern struct nla_policy ipacc_ip_policy[IPACC_IP_ATTR_MAX + 1];



#ifndef  NIPQUAD
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

#endif

#ifndef  HIPQUAD
#define HIPQUAD(addr) \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[0]
#define HIPQUAD_FMT "%u.%u.%u.%u"

#endif


#endif

