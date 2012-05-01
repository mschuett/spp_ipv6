/*
 * spp_ipv6.h
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef _SPP_IPV6_H
#define	_SPP_IPV6_H

#include "spp_ipv6_common.h"
#include "spp_ipv6_ruleopt.h"

/**********************************************************************
 ** Function Prototypes                                              **
 **********************************************************************/

static void IPv6_Init(char *);
static void IPv6_Process(void *, void *);
static void IPv6_Process_ICMPv6(const SFSnortPacket *, struct IPv6_State *);
static void IPv6_Process_ICMPv6_RA(const SFSnortPacket *, struct IPv6_State *);
static void IPv6_Process_ICMPv6_RA_stateless(const SFSnortPacket *);
static void IPv6_Process_ICMPv6_NA(const SFSnortPacket *, struct IPv6_State *);
static void IPv6_Process_ICMPv6_NS(const SFSnortPacket *, struct IPv6_State *);
inline static void IPv6_UpdateStats(const SFSnortPacket *, struct IPv6_Statistics *);
inline static void IPv6_Process_ND_Options(const SFSnortPacket *, struct IPv6_State *);
inline static void IPv6_Process_Extensions(const SFSnortPacket *, struct IPv6_State *);
static void IPv6_PrintStats(int);
static void IPv6_ResetStats(int, void *);
static void IPv6_Parse(char *, struct IPv6_Config *);

static void confirm_host(struct IPv6_State *, const HOST_t *);
static void ipv6_config_print(struct IPv6_Config *);

#endif	/* _SPP_IPV6_H */
