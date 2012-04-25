/*
 * spp_ipv6_data_structs.h
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Include file for all data structures representing network state,
 * especially lists/trees/hashes with prototypes of their respective
 * insert/remove methods.
 * 
 */

#ifndef _SPP_IPV6_DATASTRUCTS_H
#define	_SPP_IPV6_DATASTRUCTS_H

#include "spp_ipv6_constants.h"
#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_ip.h"
#include "spp_ipv6_data_host.h"

/* get size of struct member */
#define member_size(type, member) sizeof(((type *)0)->member)

// some hashes store only keys, so this constant is used as a data ptr
#define HASHMARK ((void*)0xdead)

/**********************************************************************
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
    u_int32_t mem_routers;
    u_int32_t mem_hosts;
    u_int32_t mem_unconfirmed;
    bool      track_ndp;
    bool      report_prefix_change;
    bool      report_new_routers;
    bool      report_new_hosts;
    MAC_set  *router_whitelist;
    MAC_set  *host_whitelist;
    IP_set   *prefix_whitelist;
} __attribute__((packed));

struct IPv6_State {
    HOST_set *routers;   // known routers
    HOST_set *hosts;     // established hosts
    HOST_set *unconfirmed;  // ongoing duplicate detections/solicitations
    struct IPv6_Statistics *stat;
    struct IPv6_Config     *config;
} __attribute__((packed));

/*
 * RA packet format
 */
struct ICMPv6_RA {
    /* fixed part */
    struct _ICMP6 icmp6h;
    u_int8_t  nd_ra_cur_hop_limit;
    union {
        u_int8_t m:1,
                 o:1,
                 h:1,
               prf:2,
               res:3;
        u_int8_t all;
    } flags;
    u_int16_t nd_ra_lifetime;
    u_int32_t nd_ra_reachable;
    u_int32_t nd_ra_retransmit;
} __attribute__((packed));

#endif	/* _SPP_IPV6_DATASTRUCTS_H */
