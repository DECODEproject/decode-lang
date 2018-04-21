/*  Zenroom (DECODE project)
 *
 *  (c) Copyright 2017-2018 Dyne.org foundation
 *  designed, written and maintained by Denis Roio <jaromil@dyne.org>
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Public License as published
 * by the Free Software Foundation; either version 3 of the License,
 * or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * Please refer to the GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License along with
 * this source code; if not, write to:
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <errno.h>
#include <jutils.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <lua_functions.h>

#include <zenroom.h>
#include <zen_error.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

extern int lualibs_load_all_detected(lua_State *L);
extern int lua_cjson_safe_new(lua_State *l);
extern int lua_cjson_new(lua_State *l);
extern void zen_add_io(lua_State *L);

// from lualibs_detected (generated by make embed-lua)
extern zen_extension_t zen_extensions[];
// extern unsigned char zen_lua_init[];
// extern unsigned int zen_lua_init_len;

// extern int luaopen_crypto(lua_State *L);
extern int luaopen_octet(lua_State *L);
extern int luaopen_rsa(lua_State *L);
extern int luaopen_ecdh(lua_State *L);


luaL_Reg lualibs[] = {
	{LUA_LOADLIBNAME, luaopen_package},
	{LUA_COLIBNAME,   luaopen_coroutine},
	{LUA_TABLIBNAME,  luaopen_table},
	{LUA_IOLIBNAME,   luaopen_io},
	{LUA_OSLIBNAME,   luaopen_os},
	{LUA_STRLIBNAME,  luaopen_string},
	{LUA_MATHLIBNAME, luaopen_math},
	{LUA_UTF8LIBNAME, luaopen_utf8},
	{LUA_DBLIBNAME,   luaopen_debug},
#if defined(LUA_COMPAT_BITLIB)
	{LUA_BITLIBNAME,  luaopen_bit32},
#endif
	{NULL, NULL}
};


int zen_load_string(lua_State *L, const char *code,
                    size_t size, const char *name) {
	int res;
	res = luaL_loadbufferx(L,code,size,name,"b");
	switch (res) {
	case LUA_OK: { func(L, "%s OK %s",__func__,name); break; }
	case LUA_ERRSYNTAX: { error(L, "%s syntax error: %s",__func__,name); break; }
	case LUA_ERRMEM: { error(L, "%s out of memory: %s",__func__, name); break;  }
	case LUA_ERRGCMM: {
		error(L, "%s garbage collection error: %s",__func__, name);
		break; }
	}
	return(res);
}

int zen_require(lua_State *L) {
	SAFE(L);
	size_t len;
	const char *s = lua_tolstring(L, 1, &len);
	HEREs(s);
	if(!s) return 0;
	// require classic lua libs
	for (luaL_Reg *p = lualibs;
	     p->name != NULL; ++p) {
		if (strcmp(p->name, s) == 0) {
			HEREp(p->func);
			luaL_requiref(L, p->name, p->func, 1);
			act(L,"loaded %s",p->name);
			return 1;
		}
	}
	// SAFE(zen_extensions);
	zen_extension_t *p;
	// require our own lua extensions (generated by embed-lua)
	for (p = zen_extensions;
	     p->name != NULL; ++p) {
		// skip init (called as last)
		if (strcasecmp(p->name, "init") == 0) continue;
		if (strcasecmp(p->name, s) == 0) {
			HEREp(p->code);
#ifdef __EMSCRIPTEN__
			if(p->code) {
				HEREs(p->code);
				if(luaL_loadfile(L, p->code)==0) {
					if(lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_OK) {
						act(L,"loaded %s", p->name);
						return 1;
					}
				}
			}
#else
			if(zen_load_string(L, p->code, *p->size, p->name)
			   ==LUA_OK) {
				lua_call(L,0,1);
				act(L,"loaded %s", p->name);
				return 1;
			}
#endif
			lerror(L,"%s %s",__func__,s); // quits with SIGABRT
			return 0;
		}
	}


	// require our own C to lua extensions
	// if     (strcmp(s, "crypto")==0) {
	//  luaL_requiref(L, s, luaopen_crypto, 1); return 1; }
	if(strcasecmp(s, "octet")  ==0) {
		luaL_requiref(L, s, luaopen_octet, 1); }
	// else if(strcmp(s, "rsa")  ==0) {
	//  luaL_requiref(L, s, luaopen_rsa, 1);    return 1; }
	else if(strcasecmp(s, "ecdh")  ==0) {
		luaL_requiref(L, s, luaopen_ecdh, 1); }
	else if(strcasecmp(s, "json")  ==0) {
		luaL_requiref(L, s, lua_cjson_safe_new, 1); }
	else if(strcasecmp(s, "cjson_full") ==0) {
		luaL_requiref(L, s, lua_cjson_new, 1); }
	else {
		// shall we bail out and abort execution here?
		warning(L, "required extension not found: %s",s);
		return 0; }
	act(L,"loaded %s",s);
	return 1;
}

int zen_require_override(lua_State *L) {
	static const struct luaL_Reg custom_require [] =
		{ {"require", zen_require}, {NULL, NULL} };
	lua_getglobal(L, "_G");
	luaL_setfuncs(L, custom_require, 0);
	lua_pop(L, 1);
	return 1;
}

void zen_load_extensions(lua_State *L) {
	act(L, "loading language extensions");
	SAFE(L);

	// register our own print and io.write
	zen_add_io(L);

	zen_require_override(L);

	// // at last the initialisation (see src/lua/zen_lua_init.lua)
	// if(zen_load_string(L,zen_lua_init,
	//                    zen_lua_init_len, "zen_lua_init")==LUA_OK)
	//  lua_call(L,0,1);
	// TODO: breaks in js, removed for now (all init must be explicit)

	act(L, "done loading all extensions");
}

int zen_lua_init(lua_State *L) {
	act(L, "loading lua initialisation");
	zen_extension_t *p;
	for (p = zen_extensions;
	     p->name != NULL; ++p) {
		if (strcmp(p->name, "init") == 0) {
			HEREp(p->code);
#ifdef __EMSCRIPTEN__
			if(p->code) {
				HEREs(p->code);
				if(luaL_loadfile(L, p->code)==0)
					if(lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_OK)
						return 1;
			}
#else
			if(zen_load_string(L, p->code, *p->size, p->name)
			   ==LUA_OK) {
				lua_call(L,0,1);
				return 1;
			}
#endif
			lerror(L,"%s: error loading lua init script",__func__);
		}
	}
	lerror(L,"%s: error loading lua init script",__func__);
	return 0;
}
