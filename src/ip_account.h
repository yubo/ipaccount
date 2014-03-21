/*
 *   Author:      yubo <yubo@xiaomi.com> 
 *                This program is free software; you can redistribute it and/or
 *                modify it under the terms of the GNU General Public License
 *                as published by the Free Software Foundation; either version
 *                2 of the License, or (at your option) any later version.
 **/

#ifndef _IP_ACCOUNT_H
#define _IP_ACCOUNT_H


#define _IP_ACC_DEBUG 1

#define ACCOUNT_MAX_TABLES 128
#define ACCOUNT_TABLE_NAME_LEN 32
#define ACCOUNT_MAX_HANDLES 10

#define LAN_DEFAULT_NET (1 | (2 << 8) | (0 << 16))
#define LAN_DEFAULT_MASK 0x0000ffff
#define LAN_DEFAULT_NAME "lan"


#ifdef __KERNEL__

#ifdef HNDCTF
extern int (*ctf_skb_rx_accounter)(const struct sk_buff *skb);
#endif
extern int (*skb_rx_accounter)(const struct sk_buff *skb);
extern int (*skb_tx_accounter)(const struct sk_buff *skb);



#define eLog(msg, ...)						\
	do {							\
		pr_err(msg, ##__VA_ARGS__);			\
	} while (0)


#ifdef _IP_ACC_DEBUG

#define EnterFunction()						\
	do {							\
		printk(						\
		       pr_fmt("Enter: %s, %s line %i\n"),	\
		       __func__, __FILE__, __LINE__);		\
	} while (0)
#define LeaveFunction()						\
	do {							\
		printk(						\
		       pr_fmt("Leave: %s, %s line %i\n"),	\
		       __func__, __FILE__, __LINE__);		\
	} while (0)
#define dLog(msg, ...)						\
	do {							\
		printk(msg, ##__VA_ARGS__);			\
	} while (0)

#else
#define EnterFunction()   do {} while (0)
#define LeaveFunction()   do {} while (0)
#define dLog(msg, ...)    do {} while (0)

#endif

#else

/* not in kernel */

#define eLog(msg, ...)						\
	do {							\
		fprintf(stderr, ##__VA_ARGS__);			\
	} while (0)



#ifdef _IP_ACC_DEBUG

#define dLog(msg, ...)						\
	do {							\
		fprintf(stderr, ##__VA_ARGS__);			\
	} while (0)

#else

#define dLog(msg, ...)    do {} while (0)

#endif



#endif

/*
 *
 * IPACC Generic Netlink interface definitions
 *
 */

/* Generic Netlink family info */

#define IPACC_GENL_NAME      "IPACC"
#define IPACC_GENL_VERSION   0x1

/* Generic Netlink command attributes */
enum {
    IPACC_CMD_UNSPEC = 0,
    IPACC_CMD_GET_IPS_PRE,
    IPACC_CMD_GET_IPS_PRE_FLUSH,
    IPACC_CMD_GET_IPS,
    IPACC_CMD_SET_HANDLE,
    IPACC_CMD_GET_TABLE_NAMES,
    IPACC_CMD_SET_TABLE,
    IPACC_CMD_ADD_TABLE,
    IPACC_CMD_DEL_TABLE,
    __IPACC_CMD_MAX,
};

#define IPACC_CMD_MAX (__IPACC_CMD_MAX - 1)

/* Attributes used in the first level of commands */
enum {
    IPACC_CMD_ATTR_UNSPEC = 0,
    IPACC_CMD_ATTR_TABLE,      /* nested table attribute */
    IPACC_CMD_ATTR_IP,
    IPACC_CMD_ATTR_HANDLE_NR,
    __IPACC_CMD_ATTR_MAX,
};

#define IPACC_CMD_ATTR_MAX (__IPACC_CMD_ATTR_MAX - 1)

/*
 * Attributes used to describe a service
 *
 * Used inside nested attribute IPACC_CMD_ATTR_TABLE
 */
enum {
    IPACC_TABLE_ATTR_UNSPEC = 0,
    IPACC_TABLE_ATTR_NET_IP,
    IPACC_TABLE_ATTR_NET_MASK,
    IPACC_TABLE_ATTR_NAME,
    IPACC_TABLE_ATTR_NR,
    __IPACC_TABLE_ATTR_MAX,
};

#define IPACC_TABLE_ATTR_MAX (__IPACC_TABLE_ATTR_MAX - 1)


enum {
    IPACC_IP_ATTR_UNSPEC = 0,
    IPACC_IP_ATTR_IP,
    IPACC_IP_ATTR_SRC_PACKETS,
    IPACC_IP_ATTR_SRC_BYTES,
    IPACC_IP_ATTR_DST_PACKETS,
    IPACC_IP_ATTR_DST_BYTES,
    __IPACC_IP_ATTR_MAX,
};

#define IPACC_IP_ATTR_MAX (__IPACC_IP_ATTR_MAX - 1)





/* Structure for the userspace part of ip_ACCOUNT */
struct ip_acc_info {
    __be32 net_ip;
    __be32 net_mask;
    char table_name[ACCOUNT_TABLE_NAME_LEN];
    int32_t table_nr;
};

struct ip_acc_table_user_kern {
    __be32 net_ip;
    __be32 net_mask;
    char *table_name;
    int32_t table_nr;	
};



/* Handle structure for communication with the userspace library */
struct ip_acc_handle_opt {
	uint32_t handle_nr;			/* Used for HANDLE_FREE */
	char *name[ACCOUNT_TABLE_NAME_LEN];	/* Used for HANDLE_PREPARE_READ/
							HANDLE_READ_FLUSH */
	uint32_t itemcount;			/* Used for HANDLE_PREPARE_READ/
							HANDLE_READ_FLUSH */
};

/* Handle structure for communication with the userspace library */
struct ip_acc_handle_opt_user_kern {
	uint32_t handle_nr;			/* Used for HANDLE_FREE */
	char *name;				/* Used for HANDLE_PREPARE_READ/
							HANDLE_READ_FLUSH */
	uint32_t itemcount;			/* Used for HANDLE_PREPARE_READ/
							HANDLE_READ_FLUSH */
};



/*
    Used for every IP when returning data
*/
struct ip_acc_handle_ip {
    __be32 ip;
    uint32_t src_packets;
    uint32_t src_bytes;
    uint32_t dst_packets;
    uint32_t dst_bytes;
};


struct ip_acc_ip_entry {
    __be32 ip;
    uint32_t src_packets;
    uint32_t src_bytes;
    uint32_t dst_packets;
    uint32_t dst_bytes;
};


struct ip_acc_table_entry {
	/* which service: user fills in these */
	__be32 net_ip;
	__be32 net_mask;
	char table_name[ACCOUNT_TABLE_NAME_LEN];
	int32_t table_nr;
};


/* The argument to IP_ACC_SO_GET_SERVICES */
struct ip_acc_get_ips {
	/* number of tables */
	unsigned int		num_ips;

	/* service table */
	struct ip_acc_ip_entry entryip[0];
};



/* The argument to IP_ACC_SO_GET_SERVICES */
struct ip_acc_get_tables {
	/* number of tables */
	unsigned int		num_tables;

	/* service table */
	struct ip_acc_table_entry entrytable[0];
};





#endif
