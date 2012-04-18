/*
 * spp_ipv6_data_structs.h
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Include file for all data structures representing network state,
 * especially lists and trees with prototypes of their respective
 * insert/remove methods.
 * 
 */

#ifndef DATASTRUCTS_H
#define	DATASTRUCTS_H
#include "spp_ipv6_common.h"

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

/* return values for list operations */
typedef enum _list_op_return_values {
    LISTOP_ADDED = 0, // entry added
    LISTOP_UPDATED,   // entry updatet (e.g. new timestamp)
    LISTOP_EXISTS,    // entry already exists, no change
    LISTOP_ERROR      // error, e.g. malloc() failed
} LISTOP_RET;

/*
 * State for this module, i.e. seen hosts and adresses.
 * (current size: 60 bytes on i386, 88 bytes on amd64)
 */

// second level is a tree of IPs (per MAC)
struct IPv6_Host {
    // common data for all hosts
    RB_ENTRY(IPv6_Host) entries;
    u_int8_t ether_source[6];
    time_t last_adv_ts;
    sfip_t ip;
    // extra data for routers/DAD detection
    union {
        struct {
            sfip_t *prefix;
            u_int16_t lifetime;
            union {
                u_int8_t m:1,
                         o:1,
                         h:1,
                       prf:2;
                u_int8_t all;
            } flags;
        } router;
        struct {
            sfip_t *noprefix;    // FIXME: currently only non-NULL in this field indicates a router entry
            u_int32_t contacted; // count if any 2nd host sends request
        } dad;
    } type;
};
RB_HEAD(IPv6_Hosts_data, IPv6_Host);

struct IPv6_Hosts_head {
    struct IPv6_Hosts_data data;
    u_int32_t entry_limit;
    u_int32_t entry_counter;
};

/*
 * this struct has two uses:
 *   - with ips = NULL it holds a list of MAC addresses for configuration options
 *   - with ips set it is the first level of state information
 */
struct MAC_Entry {
    RB_ENTRY(MAC_Entry) entries;
    u_int8_t mac[6];
    struct IPv6_Hosts_head *ips;
} __attribute__((aligned));
RB_HEAD(MAC_Entry_data, MAC_Entry);

struct MAC_Entry_head {
    struct MAC_Entry_data data;
    u_int32_t entry_limit;
    u_int32_t entry_counter;
};

// List because it has few entries and may use prefixes instead of IPs
struct IP_List {
    STAILQ_ENTRY(IP_List) entries;
    sfip_t *ip;
};
STAILQ_HEAD(IP_List_head, IP_List);

/*
 * Note on the data structures used:
 *  o configuration settings
 *    - router_whitelist, host_whitelist
 *      each is one rb-tree of MAC_List entries
 *    - prefix_whitelist
 *      is one stailq of IP_List
 *  o network state
 *    - routers, hosts, unconfirmed/dads
 *      each one is an rb-tree of IPv6_Host entries
 *
 */

/**********************************************************************
 ** Function Prototypes                                              **
 **********************************************************************/
void confirm_host(
    const SFSnortPacket *p,
    struct IPv6_State *context,
    const sfip_t* ip_src
) __attribute__((nonnull(1, 2)));
LISTOP_RET state_host_add(
    struct IPv6_Hosts_head*,
    struct IPv6_Host**,
    const struct timeval*,
    const u_int8_t[],
    const sfip_t*
) __attribute__((nonnull(1, 3, 4, 5)));
LISTOP_RET state_router_add(
    struct IPv6_Hosts_head*,
    struct IPv6_Host **,
    const struct timeval*,
    const u_int8_t[],
    const sfip_t*,
    sfip_t*,
    struct ICMPv6_RA*
) __attribute__((nonnull(1, 3, 4, 5, 6)));
u_int32_t state_host_expirelist(
    struct IPv6_Hosts_head*,
    time_t,
    time_t
) __attribute__((nonnull));
size_t state_host_memusage(
    struct IPv6_Hosts_head*
) __attribute__((nonnull));
void state_host_printlist(
    struct IPv6_Hosts_head *
) __attribute__((nonnull));
char *pprint_mac(
    const u_int8_t[]
) __attribute__((nonnull));
char *pprint_ts(
    const time_t ts
);
void mac_parse(
    const char* string,
    u_int8_t dst[]
)__attribute__((nonnull));
void mac_add(
    struct MAC_Entry_head*,
    const char*
)__attribute__((nonnull));
short mac_cmp(
    struct MAC_Entry*,
    struct MAC_Entry*
)__attribute__((nonnull));
short host_cmp(
    struct IPv6_Host*,
    struct IPv6_Host*
)__attribute__((nonnull));
void add_ip(
    struct IP_List_head*,
    sfip_t*
)__attribute__((nonnull));
bool ip_inprefixlist(
    struct IP_List_head*,
    sfip_t*
)__attribute__((nonnull,unused));
bool ip_inlist(
    struct IP_List_head*,
    sfip_t*
)__attribute__((nonnull));
struct IPv6_Host *get_machost_entry(
    struct MAC_Entry_head*,
    const u_int8_t[],
    const sfip_t*
)__attribute__((nonnull,unused));
struct MAC_Entry *get_mac_entry(
    struct MAC_Entry_head*,
    const u_int8_t[]
)__attribute__((nonnull));
struct MAC_Entry *create_mac_entry(
    struct MAC_Entry_head*,
    const u_int8_t[]
)__attribute__((malloc,nonnull,unused));
struct IPv6_Host *get_host_entry(
    struct IPv6_Hosts_head*,
    const sfip_t*
)__attribute__((nonnull));
struct IPv6_Host *create_host_entry(
    struct IPv6_Hosts_head*,
    const struct timeval*,
    const u_int8_t[],
    const sfip_t*
)__attribute__((malloc,nonnull));
struct IPv6_Host *create_dad_entry_ifnew(
    struct IPv6_Hosts_head*,
    const struct timeval*,
    const u_int8_t[],
    const sfip_t*
)__attribute__((malloc,nonnull)); //create_host_entry_ifnew
void del_host_entry(
    struct IPv6_Hosts_head*,
    struct IPv6_Host*
)__attribute__((nonnull));
void del_dad_entry(
    struct IPv6_Hosts_head*,
    struct IPv6_Host*
)__attribute__((nonnull));

RB_PROTOTYPE(MAC_Entry_data,  MAC_Entry, entries, mac_cmp);
RB_PROTOTYPE(IPv6_Hosts_data, IPv6_Host, entries, host_cmp);

#endif	/* DATASTRUCTS_H */
