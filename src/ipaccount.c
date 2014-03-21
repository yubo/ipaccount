/***************************************************************************
 *   Copyright (C) 2004-2006 by Intra2net AG                               *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License           *
 *   version 2.1 as published by the Free Software Foundation;             *
 *                                                                         *
 ***************************************************************************/


/*
 *   Author:      yubo <yubo@xiaomi.com> 
 *                This program is free software; you can redistribute it and/or
 *                modify it under the terms of the GNU General Public License
 *                as published by the Free Software Foundation; either version
 *                2 of the License, or (at your option) any later version.
 **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/types.h>

#include <netdb.h>

#include "ipaccount.h"

bool exit_now;
static void sig_term(int signr){
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    exit_now = true;
}

static void show_usage(void){
    printf("Unknown command line option. Try: [-u] [-h] [-a] [-f] [-c] [-s] [-l name]\n");
    printf("-A -n name -N x.x.x.x/x.x.x.x\n");
    printf("-D -n name\n");
    printf("-S -n name -N x.x.x.x/x.x.x.x\n");
    printf("[-u] show kernel handle usage\n");
    printf("[-h] free all kernel handles (experts only!)\n\n");
    printf("[-a] list all table names\n");
    printf("[-l -n name] show data in table <name>\n");
    printf("[-f] flush data after showing\n");
    printf("[-c] loop every second (abort with CTRL+C)\n");
    printf("[-s] CSV output (for spreadsheet import)\n");
    printf("[-C] clear output (data only)\n");
    printf("[-S] set tab\n");
    printf("[-A] add table\n");
    printf("[-D] drop table  \n");
    printf("[-n name] set table name\n");
    printf("[-N x.x.x.x/x.x.x.x] set network/netmask\n");
    printf("\n");
}


static int host_to_addr(const char *name, struct in_addr *addr){
    struct hostent *host;

    if ((host = gethostbyname(name)) != NULL) {
        if (host->h_addrtype != AF_INET ||
                host->h_length != sizeof(struct in_addr))
            return -1;
        /* warning: we just handle h_addr_list[0] here */
        memcpy(addr, host->h_addr_list[0], sizeof(struct in_addr));
        return 0;
    }
    return -1;
}


/*
 * Get netmask.
 */
static int parse_net_mask(char *buf, u_int32_t *net, u_int32_t *mask){
    struct in_addr inaddr;
    char *n, *m;

    if(buf == NULL)
        return 1;

    n = buf;
    m = strchr(buf, '/');
    if(m == NULL)
        return 1;

    *m = '\0';
    m++;

    if (inet_aton(n, &inaddr) != 0)
        *net = inaddr.s_addr;
    else if (host_to_addr(n, &inaddr) != -1)
        *net = inaddr.s_addr;
    else
        return 1;

    if (inet_aton(m, &inaddr) != 0)
        *mask = inaddr.s_addr;
    else if (host_to_addr(m, &inaddr) != -1)
        *mask = inaddr.s_addr;
    else
        return 1;

    return 0;
}



static void
print_table_entry(struct ip_acc_table_entry *te)
{
	printf("%3d %16s %u.%u.%u.%u/%u.%u.%u.%u\n",te->table_nr, te->table_name, 
		NIPQUAD(te->net_ip), NIPQUAD(te->net_mask));
}




static void list_tables(void)
{
    struct ip_acc_get_tables *get;
    int i;

    if(!(get = ipacc_get_tables())){
    	fprintf(stderr, "list_tables error\n");
	exit(1);
    }
    
    for (i = 0; i < get->num_tables; i++)
	    print_table_entry(&get->entrytable[i]);
    free(get);
}


static void
print_ip_entry(struct ip_acc_ip_entry *ie)
{
	printf("%u.%u.%u.%u\t%u\t%u\t%u\t%u\n",HIPQUAD(ie->ip), ie->src_bytes, ie->src_packets,
		ie->dst_bytes, ie->dst_packets);
}



static void list_ips(struct ip_acc_table_user_kern*itb)
{
    struct ip_acc_get_ips *get;
    int i;

    if(!(get = ipacc_get_ips(itb))){
    	fprintf(stderr, "list_ips error\n");
	exit(1);
    }
    
    for (i = 0; i < get->num_ips; i++)
	    print_ip_entry(&get->entryip[i]);
    free(get);
}


int main(int argc, char *argv[]){
    struct ip_acc_table_user_kern itb = {
    	.table_name = NULL,
    	.net_ip = 0,
    	.net_mask = 0,
    	.table_nr = -1,
    	};
    int ret;
    int optchar;
    bool doTableNames = false;
    bool doFlush = false, doContinue = false;
    bool doDropTab = false, doAddTab = false, doSetTab = false, doListIP = false;


    if (argc == 1) {
        show_usage();
        exit(0);
    }

    while ((optchar = getopt(argc, argv, "acflADSN:n:")) != -1) {
        switch (optchar) {
            case 'a':
                doTableNames = true;
                break;
            case 'f':
                doFlush = true;
                break;
            case 'c':
                doContinue = true;
                break;
            case 'l':
	    	doListIP = true;
	    	break;
            case 'n':
                itb.table_name = strdup(optarg);
                break;
            case 'S':
                doSetTab = true;
                break;
            case 'A':
                doAddTab = true;
                break;
            case 'D':
                doDropTab = true;
                break;
            case 'N':
                parse_net_mask(optarg, &itb.net_ip, &itb.net_mask);
		break;
            case '?':
            default:
                show_usage();
                exit(0);
                break;
        }
    }

    // install exit handler
    if (signal(SIGTERM, sig_term) == SIG_ERR) {
        printf("can't install signal handler for SIGTERM\n");
        exit(-1);
    }
    if (signal(SIGINT, sig_term) == SIG_ERR) {
        printf("can't install signal handler for SIGINT\n");
        exit(-1);
    }
    if (signal(SIGQUIT, sig_term) == SIG_ERR) {
        printf("can't install signal handler for SIGQUIT\n");
        exit(-1);
    }


    if (ip_acc_init()) {
        printf("ip_acc_init failed\n");
        exit(-1);
    }



    if (doSetTab) {
        if(itb.table_name == NULL) {
            printf("need table name( -n xxx )\n");
            exit(-1);
        } 
        if(itb.net_ip == 0 || itb.net_mask== 0) {
            printf("net/mask error(-N x.x.x.x/x.x.x.x )\n");
            exit(-1);
        }	
	ret = ipacc_set_table(&itb);
	if(ret){
		if (errno == ESRCH)
			fprintf(stderr, "No such table (%s)\n", itb.table_name);
		exit(ret);
	}
        return EXIT_SUCCESS;

    }    


    if (doDropTab) {
        if(itb.table_name == NULL) {
            printf("need table name( -n xxx )\n");
            exit(-1);
        } 
	ret = ipacc_del_table(&itb);
	if(ret){
		if (errno == ESRCH)
			fprintf(stderr, "No such table (%s)\n", itb.table_name);
		if (errno == EPERM)
			fprintf(stderr, "Permission denied (you can not delete %s)\n", itb.table_name);
		exit(ret);
	}
        return EXIT_SUCCESS;

    }

    if (doAddTab) {
        if(itb.table_name == NULL) {
            printf("need table name( -n xxx )\n");
            exit(-1);
        }
        if(itb.net_ip == 0 || itb.net_mask== 0) {
            printf("net/mask error(-N x.x.x.x/x.x.x.x )\n");
            exit(-1);
        }
	ret = ipacc_add_table(&itb);
	if(ret){
		if (errno == EEXIST)
			fprintf(stderr, "table name (%s)already exists\n", itb.table_name);
		exit(ret);
	}
        return EXIT_SUCCESS;
    }

    if (doSetTab) {
        if(itb.table_name == NULL) {
            printf("need table name( -n xxx )\n");
            exit(-1);
        }
        if(itb.net_ip == 0 || itb.net_mask == 0) {
            printf("net/mask error(-N x.x.x.x/x.x.x.x )\n");
            exit(-1);
        }
        printf("set lan net(0x%x/0x%x)\n", itb.net_ip, itb.net_mask);
        return EXIT_SUCCESS;
    }


    if (doTableNames) {
        list_tables();
        exit(0);
    }

    if (doListIP && itb.table_name) {
    	list_ips(&itb);
	exit(0);
    }


    ip_acc_deinit();
    return EXIT_SUCCESS;
}

