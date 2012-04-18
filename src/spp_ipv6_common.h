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

<<<<<<< HEAD
#ifndef _SPP_IPV6_COMMON_H
#define	_SPP_IPV6_COMMON_H
=======
#ifndef _SPP_IPV6_H
#define	_SPP_IPV6_H
>>>>>>> d3c75260618737d57f8edd18687983944a621490

/**********************************************************************
 ** Includes                                                         **
 **********************************************************************/
#include "../include/sf_types.h"
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/queue.h>
<<<<<<< HEAD
#include <errno.h>
=======
>>>>>>> d3c75260618737d57f8edd18687983944a621490

#ifdef __linux__
#ifndef __unused
#define __unused __attribute__((__unused__)) 
#endif /* __unused */
#include "tree.h"
#else /* BSD */
#include <sys/tree.h>
#endif /* __linux__  */

#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
/* for ICMPv6 format */
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

<<<<<<< HEAD
#include "spp_ipv6_constants.h"
#include "spp_ipv6_data_structs.h"

=======
>>>>>>> d3c75260618737d57f8edd18687983944a621490
/* verify string contains a MAC address */
#define IS_MAC(string) ((string) != NULL                                     \
  && isxdigit((string)[ 0]) && isxdigit((string)[ 1]) && (string)[ 2] == ':' \
  && isxdigit((string)[ 3]) && isxdigit((string)[ 4]) && (string)[ 5] == ':' \
  && isxdigit((string)[ 6]) && isxdigit((string)[ 7]) && (string)[ 8] == ':' \
  && isxdigit((string)[ 9]) && isxdigit((string)[10]) && (string)[11] == ':' \
  && isxdigit((string)[12]) && isxdigit((string)[13]) && (string)[14] == ':' \
  && isxdigit((string)[15]) && isxdigit((string)[16]) && (string)[17] == '\0')


/**********************************************************************
<<<<<<< HEAD
 ** Function Prototypes                                              **
 **********************************************************************/

#endif	/* _SPP_IPV6_COMMON_H */
=======
 ** Structures/Data Types                                            **
 **********************************************************************/

/*
 * Some simple statistics.
 * TODO: only for data exploration; to be removed later on
 */
struct IPv6_Statistics {
    uint32_t pkt_seen;
    uint32_t pkt_invalid;
    uint32_t pkt_icmpv6;
    uint32_t pkt_other;

    uint32_t pkt_fragments;

    uint32_t pkt_ip6h;

    uint32_t pkt_icmp_rsol;
    uint32_t pkt_icmp_radv;
    uint32_t pkt_icmp_nsol;
    uint32_t pkt_icmp_nadv;

    uint32_t pkt_icmp_mlquery;
    uint32_t pkt_icmp_mlreport;
    uint32_t pkt_icmp_unreach;
    uint32_t pkt_icmp_other;
};

/*
 * configuration and plugin state.
 */
struct IPv6_Config {
    u_int32_t keep_state_duration;  // in sec
    u_int32_t expire_run_interval;  // in sec
    u_int32_t max_routers;
    u_int32_t max_hosts;
    u_int32_t max_unconfirmed;
    bool      track_ndp;
    bool      report_prefix_change;
    bool      report_new_routers;
    bool      report_new_hosts;
    struct MAC_Entry_head *router_whitelist;
    struct MAC_Entry_head *host_whitelist;
    struct IP_List_head   *prefix_whitelist;
} __attribute__((packed));

struct IPv6_State {
    struct IPv6_Hosts_head *routers;   // known routers
    struct IPv6_Hosts_head *hosts;     // established hosts
    struct IPv6_Hosts_head *unconfirmed;  // ongoing duplicate detections/solicitations
    struct IPv6_Statistics *stat;
    struct IPv6_Config     *config;
    time_t next_expire;
} __attribute__((packed));

/*
 * for Rule Options
 */
enum IPv6_RuleOpt_Type {
    IPV6_RULETYPE_IPV,
    IPV6_RULETYPE_IP6EXTHDR,
    IPV6_RULETYPE_IP6EXTCOUNT,
    IPV6_RULETYPE_FLOWLABEL,
    IPV6_RULETYPE_TRAFFICCLASS,
    IPV6_RULETYPE_OPTION,
    IPV6_RULETYPE_OPTION_EXT,
    IPV6_RULETYPE_OPTVAL,
    IPV6_RULETYPE_ND,
    IPV6_RULETYPE_ND_OPTION,
    IPV6_RULETYPE_RH,
    IPV6_RULETYPE_EXT_ORDERED
};

enum cmp_op {
    check_eq=0, check_neq,
    check_lt, check_gt,
    check_and, check_xor, check_nand
};

struct IPv6_RuleOpt_Data {
#ifdef DEBUG
    char *debugname;
    char *debugparam;
#endif /* DEBUG */
    enum IPv6_RuleOpt_Type type:4;
    enum cmp_op op:4;
    union {
            u_int32_t number;
            struct { // for ip6_optval
                u_int8_t  ext_type;
                u_int8_t  opt_type;
                u_int16_t opt_value;
            } exthdr;
    } opt;
} __attribute__((packed));

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

static int IPv6_Rule_Init(char *, char *, void **);
static int IPv6_Rule_Eval(void *, const u_int8_t **, void *);
static u_int32_t IPv6_Rule_Hash(void *);
static int IPv6_Rule_KeyCompare(void *, void *);

#endif	/* _SPP_IPV6_H */
>>>>>>> d3c75260618737d57f8edd18687983944a621490
