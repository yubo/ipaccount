/*
 *   Author:      yubo <yubo@xiaomi.com> 
 *                This program is free software; you can redistribute it and/or
 *                modify it under the terms of the GNU General Public License
 *                as published by the Free Software Foundation; either version
 *                2 of the License, or (at your option) any later version.
 **/


#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <errno.h>

#include "ipaccount.h"



static struct nl_handle *sock = NULL;
static int family;
uint32_t handle_nr;

/* Policy used for attributes in nested attribute IPACC_CMD_ATTR */
struct nla_policy ipacc_cmd_policy[IPACC_CMD_ATTR_MAX + 1] = {
    [IPACC_CMD_ATTR_TABLE] = {.type = NLA_NESTED},
    [IPACC_CMD_ATTR_IP] = {.type = NLA_NESTED},
    [IPACC_CMD_ATTR_HANDLE_NR] = {.type = NLA_U32},    
};

/* Policy used for attributes in nested attribute IPACC_CMD_ATTR_TABLE */
struct nla_policy ipacc_table_policy[IPACC_TABLE_ATTR_MAX + 1] = {
    [IPACC_TABLE_ATTR_NET_IP] = {.type = NLA_U32},
    [IPACC_TABLE_ATTR_NET_MASK] = {.type = NLA_U32},
    [IPACC_TABLE_ATTR_NAME] = {.type = NLA_STRING,
                    .maxlen = ACCOUNT_TABLE_NAME_LEN},
    [IPACC_TABLE_ATTR_NR] = {.type = NLA_U32},
};

/* Policy used for attributes in nested attribute IPACC_CMD_ATTR_NODE */
struct nla_policy ipacc_ip_policy[IPACC_IP_ATTR_MAX + 1] = {
    [IPACC_IP_ATTR_IP] = {.type = NLA_U32},
    [IPACC_IP_ATTR_SRC_PACKETS] = {.type = NLA_U32},
    [IPACC_IP_ATTR_SRC_BYTES] = {.type = NLA_U32},
    [IPACC_IP_ATTR_DST_PACKETS] = {.type = NLA_U32},
    [IPACC_IP_ATTR_DST_BYTES] = {.type = NLA_U32},
};





static struct nl_msg *ipacc_nl_message(int cmd, int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, flags,
		    cmd, IPACC_GENL_VERSION);

	return msg;
}

static int ipacc_nl_noop_cb(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static int ipacc_nl_send_message(struct nl_msg *msg, nl_recvmsg_msg_cb_t func, void *arg)
{
	int err = EINVAL;

	sock = nl_handle_alloc();
	if (!sock) {
		nlmsg_free(msg);
		return -1;
	}

	if (genl_connect(sock) < 0)
		goto fail_genl;

	family = genl_ctrl_resolve(sock, IPACC_GENL_NAME);
	if (family < 0)
		goto fail_genl;

	/* To test connections and set the family */
	if (msg == NULL) {
		nl_handle_destroy(sock);
		sock = NULL;
		return 0;
	}

	if (nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, func, arg) != 0)
		goto fail_genl;

	if (nl_send_auto_complete(sock, msg) < 0)
		goto fail_genl;

	if ((err = -nl_recvmsgs_default(sock)) > 0)
		goto fail_genl;

	nlmsg_free(msg);

	nl_handle_destroy(sock);

	return 0;

fail_genl:
	nl_handle_destroy(sock);
	sock = NULL;
	nlmsg_free(msg);
	errno = err;
	return -1;
}




int ip_acc_init()
{
	if (ipacc_nl_send_message(NULL, NULL, NULL)) {
	    fprintf(stderr, "genl send message error\n");
	    return -1;
	}
	return 0;
}


void ip_acc_deinit()
{
	return;
}



static int ipacc_nl_fill_table_attr(struct nl_msg *msg, struct ip_acc_table_user_kern *itb)
{
	struct nlattr *nl_table;

	nl_table = nla_nest_start(msg, IPACC_CMD_ATTR_TABLE);
	if (!nl_table)
		return -1;

	NLA_PUT_U32(msg, IPACC_TABLE_ATTR_NET_IP, itb->net_ip);
	NLA_PUT_U32(msg, IPACC_TABLE_ATTR_NET_MASK, itb->net_mask);
	NLA_PUT_STRING(msg, IPACC_TABLE_ATTR_NAME, itb->table_name);
	
	nla_nest_end(msg, nl_table);
	return 0;
	
nla_put_failure:
	return -1;	
}


int ipacc_del_table(struct ip_acc_table_user_kern *itb)
{
	struct nl_msg *msg = ipacc_nl_message(IPACC_CMD_DEL_TABLE, 0);
	if (!msg) return -1;
	if (ipacc_nl_fill_table_attr(msg, itb)) {
		nlmsg_free(msg);
		return -1;
	}
	return ipacc_nl_send_message(msg, ipacc_nl_noop_cb, NULL);
}


int ipacc_set_table(struct ip_acc_table_user_kern *itb)
{
	struct nl_msg *msg = ipacc_nl_message(IPACC_CMD_SET_TABLE, 0);
	if (!msg) return -1;
	if (ipacc_nl_fill_table_attr(msg, itb)) {
		nlmsg_free(msg);
		return -1;
	}
	return ipacc_nl_send_message(msg, ipacc_nl_noop_cb, NULL);
}



int ipacc_add_table(struct ip_acc_table_user_kern *itb)
{
	struct nl_msg *msg = ipacc_nl_message(IPACC_CMD_ADD_TABLE, 0);
	if (!msg) return -1;
	if (ipacc_nl_fill_table_attr(msg, itb)) {
		nlmsg_free(msg);
		return -1;
	}
	return ipacc_nl_send_message(msg, ipacc_nl_noop_cb, NULL);
}



static int ipacc_tables_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPACC_CMD_ATTR_MAX + 1];
	struct nlattr *table_attrs[IPACC_TABLE_ATTR_MAX + 1];
	struct ip_acc_get_tables **getp = (struct ip_acc_get_tables **)arg;
	struct ip_acc_get_tables *get = (struct ip_acc_get_tables *)*getp;
	int i = get->num_tables;

	printf("Enter %s\n", __FUNCTION__);
	if (genlmsg_parse(nlh, 0, attrs, IPACC_CMD_ATTR_MAX, ipacc_cmd_policy) != 0){
		return -1;
	}

	if (!attrs[IPACC_CMD_ATTR_TABLE])
		return -1;

	if (nla_parse_nested(table_attrs, IPACC_TABLE_ATTR_MAX, attrs[IPACC_CMD_ATTR_TABLE], ipacc_table_policy)){
		return -1;
	}

	memset(&(get->entrytable[i]), 0, sizeof(get->entrytable[i]));

	if (!(table_attrs[IPACC_TABLE_ATTR_NET_IP] &&
		table_attrs[IPACC_TABLE_ATTR_NET_MASK] &&
		table_attrs[IPACC_TABLE_ATTR_NAME] &&
		table_attrs[IPACC_TABLE_ATTR_NR])){
		return -1;
	}
	
	strncpy(get->entrytable[i].table_name,
		nla_get_string(table_attrs[IPACC_TABLE_ATTR_NAME]),
		ACCOUNT_TABLE_NAME_LEN);
	get->entrytable[i].net_ip = nla_get_u32(table_attrs[IPACC_TABLE_ATTR_NET_IP]);
	get->entrytable[i].net_mask= nla_get_u32(table_attrs[IPACC_TABLE_ATTR_NET_MASK]);
	get->entrytable[i].table_nr= nla_get_u32(table_attrs[IPACC_TABLE_ATTR_NR]);
	get->num_tables++;

	get = realloc(get, sizeof(*get) + sizeof(struct ip_acc_table_entry) * (get->num_tables + 1));
	*getp = get;

	return 0;

}






struct ip_acc_get_tables *ipacc_get_tables(void)
{
	struct ip_acc_get_tables *get;
	socklen_t len;


	struct nl_msg *msg;
	
	len = sizeof(*get) +
		sizeof(struct ip_acc_table_entry);
	if (!(get = malloc(len)))
		return NULL;
	get->num_tables = 0;

	msg = ipacc_nl_message(IPACC_CMD_GET_TABLE_NAMES, NLM_F_DUMP);
	if (msg && (ipacc_nl_send_message(msg, ipacc_tables_parse_cb, &get) == 0))
		return get;

	free(get);
	return NULL;


}



static int ipacc_ips_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPACC_CMD_ATTR_MAX + 1];
	struct nlattr *ip_attrs[IPACC_IP_ATTR_MAX + 1];
	struct ip_acc_get_ips **getp = (struct ip_acc_get_ips **)arg;
	struct ip_acc_get_ips *get = (struct ip_acc_get_ips *)*getp;
	int i = get->num_ips;

	if (genlmsg_parse(nlh, 0, attrs, IPACC_CMD_ATTR_MAX, ipacc_cmd_policy) != 0){
		return -1;
	}

	if (!attrs[IPACC_CMD_ATTR_IP])
		return -1;

	if (nla_parse_nested(ip_attrs, IPACC_IP_ATTR_MAX, attrs[IPACC_CMD_ATTR_IP], ipacc_ip_policy)){
		return -1;
	}

	memset(&(get->entryip[i]), 0, sizeof(get->entryip[i]));

	if (!(ip_attrs[IPACC_IP_ATTR_IP] &&
		ip_attrs[IPACC_IP_ATTR_SRC_PACKETS] &&
		ip_attrs[IPACC_IP_ATTR_SRC_BYTES] &&
		ip_attrs[IPACC_IP_ATTR_DST_PACKETS] &&
		ip_attrs[IPACC_IP_ATTR_DST_BYTES])){
		return -1;
	}
	

	get->entryip[i].ip = nla_get_u32(ip_attrs[IPACC_IP_ATTR_IP]);
	get->entryip[i].src_packets= nla_get_u32(ip_attrs[IPACC_IP_ATTR_SRC_PACKETS]);
	get->entryip[i].src_bytes= nla_get_u32(ip_attrs[IPACC_IP_ATTR_SRC_BYTES]);
	get->entryip[i].dst_packets= nla_get_u32(ip_attrs[IPACC_IP_ATTR_DST_PACKETS]);
	get->entryip[i].dst_bytes= nla_get_u32(ip_attrs[IPACC_IP_ATTR_DST_BYTES]);
	get->num_ips++;

	get = realloc(get, sizeof(*get) + sizeof(struct ip_acc_ip_entry) * (get->num_ips + 1));
	*getp = get;

	return 0;

}



static int ipacc_get_ips_parse_pre_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPACC_CMD_ATTR_MAX + 1];

	if (genlmsg_parse(nlh, 0, attrs, IPACC_CMD_ATTR_MAX, ipacc_cmd_policy) != 0){
		return -1;
	}

	if (!attrs[IPACC_CMD_ATTR_HANDLE_NR])
		return -1;
	
	handle_nr = nla_get_u32(attrs[IPACC_CMD_ATTR_HANDLE_NR]);


	return NL_OK;

}


struct ip_acc_get_ips *ipacc_get_ips(struct ip_acc_table_user_kern *itb)
{
	struct ip_acc_get_ips *get;

	struct nl_msg *msg;

	if (!(get = malloc(sizeof(*get) +
		sizeof(struct ip_acc_ip_entry))))
		return NULL;
	get->num_ips = 0;


	
/*
	IPACC_CMD_GET_IPS_PRE/IPACC_CMD_GET_IPS_PRE_FLUSH
*/
	msg = ipacc_nl_message(IPACC_CMD_GET_IPS_PRE, 0);
	if (!msg) 
		goto ipacc_get_ips_err;

	if (ipacc_nl_fill_table_attr(msg, itb))
		goto nla_put_failure;
	
	if (ipacc_nl_send_message(msg, ipacc_get_ips_parse_pre_cb, NULL))
		goto ipacc_get_ips_err;



/* 	IPACC_CMD_GET_IPS */
		

	msg = ipacc_nl_message(IPACC_CMD_GET_IPS, NLM_F_DUMP);
	if (!msg)
		goto ipacc_get_ips_err;


	NLA_PUT_U32(msg, IPACC_CMD_ATTR_HANDLE_NR, handle_nr);

	if (ipacc_nl_send_message(msg, ipacc_ips_parse_cb, &get))
		goto ipacc_get_ips_err;

	return get; 

nla_put_failure:
	nlmsg_free(msg);

ipacc_get_ips_err:

	free(get);

	
	return NULL;
}



