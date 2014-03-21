/*
 *   Author:      yubo <yubo@xiaomi.com> 
 *                This program is free software; you can redistribute it and/or
 *                modify it under the terms of the GNU General Public License
 *                as published by the Free Software Foundation; either version
 *                2 of the License, or (at your option) any later version.
 **/

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "ipaccount.h"


#ifndef VERSION
#  define VERSION "unknown"
#endif

#define MYNAME		"ipaccount"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / " VERSION


static int Pip_acc_init(lua_State *L)
{
	ip_acc_init();
	return 1;
}


static int Pget_account_table(lua_State *L)
{
	static char buf[16];
	int i, j;
	size_t len;
	struct ip_acc_get_ips *get;
	struct ip_acc_ip_entry *entry;
	struct ip_acc_table_user_kern itb;
	const char *table_name = luaL_checklstring(L, 1, &len);
	itb.table_name = table_name;


	lua_newtable(L);
	
	if(!(get = ipacc_get_ips(&itb))){
	    luaL_error(L, "list_ips error");
	}	
	
	for (i = 0; i < get->num_ips; ){
		entry = &get->entryip[i++];
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u", HIPQUAD(entry->ip));
		
		lua_pushnumber(L, i);
		lua_newtable(L);

		/* ip */
		lua_pushstring(L, "ip");		
		lua_pushstring(L, buf);
		lua_settable(L, -3); /* pops "ip" and buf */
		/* src_packets */
		lua_pushstring(L, "src_packets");
		lua_pushnumber(L, entry->src_packets);
		lua_settable(L, -3);
		/* src_bytes */
		lua_pushstring(L, "src_bytes");
		lua_pushnumber(L, entry->src_bytes);
		lua_settable(L, -3);
		/* dst_packets */
		lua_pushstring(L, "dst_packets");
		lua_pushnumber(L, entry->dst_packets);
		lua_settable(L, -3);
		/* dst_bytes */
		lua_pushstring(L, "dst_bytes");
		lua_pushnumber(L, entry->dst_bytes);
		lua_settable(L, -3);

		lua_settable(L, -3); /* pops i and table */
	}
	free(get);

	return 1;
}

static int Phw(lua_State *L)
{
	char b[64];
	size_t len;
	const char *s = luaL_checklstring(L, 1, &len);
	if (len + 7 >=sizeof(b))
		luaL_argerror(L, 1, "too long");
	sprintf(b, "hello: %s", s);
	lua_pushstring(L, b);
	return 1;
}



static const luaL_reg R[] =
{

	{"hw",			Phw},
	{"ip_acc_init",		Pip_acc_init},
	{"get_account_table",	Pget_account_table},
	{NULL,			NULL}
};

#define set_const(key, value)		\
	lua_pushnumber(L, value);	\
	lua_setfield(L, -2, key)


LUALIB_API int luaopen_ipaccount (lua_State *L)
{
	luaL_register(L, MYNAME, R);
	lua_pushliteral(L, MYVERSION);
	lua_setfield(L, -2, "version");
	return 1;

}




