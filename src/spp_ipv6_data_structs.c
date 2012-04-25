/*
 * spp_ipv6_data_structs.c
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Some other data struct tools, which do not fit into the MAC/IP/Host files.
 *
 */

#ifndef SPP_IPV6_DATA_STRUCTS_H
#define	SPP_IPV6_DATA_STRUCTS_H

#include <time.h>
#include <sys/time.h>
#include <stdio.h>

#include "spp_ipv6_data_structs.h"
#include "spp_ipv6_common.h"


/**********************************************************************
 ** STAILQ IP_List                                                   **
 **********************************************************************/

/**
 * Check if IP matches a prefix in list.

bool ip_inprefixlist(struct IP_List_head *listhead, sfip_t *ip)
{
    struct IP_List *entry;

    STAILQ_FOREACH(entry, listhead, entries) {
        if (SFIP_EQUAL == sfip_contains(entry->ip, ip)) {
            return true;
        }
    }
    return false;
}
 */

/**********************************************************************
 ** SFXHASH IPv6_Host                                                **
 **********************************************************************/

/**
 * add host to state
 * ip_src is optional (if NULL, then package ip_src is used)

void confirm_host(const SFSnortPacket *p,
                         struct IPv6_State *context,
                         const sfip_t* ip_src)
{
    LISTOP_RET rc;
    struct IPv6_Host *hostentry;
    const sfip_t* target_ip = ip_src ? ip_src : &p->ip6h->ip_src;

    rc = state_host_add(context->hosts,
                        &hostentry,
                        &p->pkt_header->ts,
                        p->ether_header->ether_source,
                        target_ip);
    if (rc == LISTOP_ADDED) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "confirm_host: %s new IPv6 host: %s / %s\n",
                      pprint_ts(p->pkt_header->ts.tv_sec),
                      pprint_mac(p->ether_header->ether_source),
                      sfip_to_str(target_ip)););
        if (context->config->host_whitelist
            && !macset_empty(context->config->host_whitelist)
            && macset_contains(context->config->host_whitelist, mac_set(NULL, p->ether_header->ether_source))) {
            ALERT(SID_ICMP6_INVALID_HOST_MAC);
        } else {
            ALERT(SID_ICMP6_ND_NEW_HOST);
        }
    } else if (rc == LISTOP_UPDATED) { // nothing
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "confirm_host: update timestamp for IPv6 host %s / %s\n",
                      pprint_mac(p->ether_header->ether_source),
                      sfip_to_str(target_ip)););
    } else { // (rc == LISTOP_ERROR)
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "confirm_host: cannot add state for IPv6 host %s / %s\n",
                      pprint_mac(p->ether_header->ether_source),
                      sfip_to_str(target_ip)););
    }
}
 */

#endif	/* SPP_IPV6_DATA_STRUCTS_H */