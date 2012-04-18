/*
 * spp_ipv6_data_structs.c
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Insert/remove methods all data structures representing network state,
 * especially lists and trees.
 *
 */

#include "spp_ipv6_common.h"

/**********************************************************************
 ** STAILQ IP_List                                                   **
 **********************************************************************/

/**
 * Add IP (sfip_t) to a list.
 * no input checking, arguments have to be valid.
 */
void add_ip(struct IP_List_head *listhead, sfip_t *ip)
{
    struct IP_List *entry;
    if (!(entry = (struct IP_List *) calloc(1, sizeof(struct IP_List))))
        _dpd.fatalMsg("Could not allocate IPv6 dyn-pp configuration struct.\n");

    entry->ip = ip;
    STAILQ_INSERT_TAIL(listhead, entry, entries);
}

/**
 * Check if IP matches a prefix in list.
 */
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

/**
 * Check if IP is in list.
 */
bool ip_inlist(struct IP_List_head *listhead, sfip_t *ip)
{
    struct IP_List *entry;

    STAILQ_FOREACH(entry, listhead, entries) {
        if (SFIP_EQUAL == sfip_compare(entry->ip, ip)) {
            return true;
        }
    }
    return false;
}

/**********************************************************************
 ** RB MAC_List / IPv6_Host                                          **
 **********************************************************************/

/**
 * Compare MAC addesses
 */
short mac_cmp(struct MAC_Entry *a, struct MAC_Entry *b)
{
    return memcmp(&a->mac, &b->mac, sizeof(a->mac));
}

/**
 * Compare IPv6 hosts (only by IP)
 *
 * NB: no input checking; assume two valid IPv6 addresses
 */
short host_cmp(struct IPv6_Host *a, struct IPv6_Host *b)
{
    // optimized
    return memcmp(&a->ip.ip, &b->ip.ip, sizeof(b->ip.ip));

    /* alternative with sfip api
    SFIP_RET rc;
    rc = sfip_compare(&a->ip, &b->ip);
    switch (rc) {
    case SFIP_LESSER:  return -1;
    case SFIP_GREATER: return +1;
    default:           return  0;
    }
    */
}

/**
 * Parse a string MAC into binary data
 * no input checking, arguments have to be valid
 */
void mac_parse(const char* string, u_int8_t dst[])
{
    dst[0] = (u_int8_t) strtoul(&string[ 0], NULL, 16);
    dst[1] = (u_int8_t) strtoul(&string[ 3], NULL, 16);
    dst[2] = (u_int8_t) strtoul(&string[ 6], NULL, 16);
    dst[3] = (u_int8_t) strtoul(&string[ 9], NULL, 16);
    dst[4] = (u_int8_t) strtoul(&string[12], NULL, 16);
    dst[5] = (u_int8_t) strtoul(&string[15], NULL, 16);
}

/**
 * Aux. function to format MAC address (in static buffer).
 */
char *pprint_mac(const u_int8_t ether_source[])
{
    static char buf[18];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             ether_source[0], ether_source[1],
             ether_source[2], ether_source[3],
             ether_source[4], ether_source[5]);
    return buf;
}

/**
 * Aux. function to format timestamp (in static buffer).
 */
char *pprint_ts(const time_t ts)
{
    struct tm *printtm;
    static char buf[64];

    printtm = localtime(&ts);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", printtm);

    return buf;
}


/**
 * Add string MAC to a tree.
 * no input checking, arguments have to be valid.
 *
 * TODO: merge with normal add method
 */
void mac_add(struct MAC_Entry_head *head, const char *mac)
{
    struct MAC_Entry *entry;

    if (!(entry = (struct MAC_Entry *) calloc(1, sizeof(struct MAC_Entry))))
        _dpd.fatalMsg("Could not allocate IPv6 dyn-pp configuration struct.\n");

    mac_parse(mac, entry->mac);
    RB_INSERT(MAC_Entry_data, &head->data, entry);
}

RB_GENERATE(MAC_Entry_data,  MAC_Entry, entries, mac_cmp);
RB_GENERATE(IPv6_Hosts_data, IPv6_Host, entries, host_cmp);

/**
 * deletes an IPv6_Host entry
 */
void del_host_entry(struct IPv6_Hosts_head *head,
                           struct IPv6_Host *ip)
{
    if (RB_REMOVE(IPv6_Hosts_data, &head->data, ip)) {
        sfip_free(ip->type.router.prefix);
        free(ip);
        head->entry_counter--;
    } else {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "del_host_entry: RB_REMOVE failed\n"););
    }
}

/**
 * creates an IPv6_Host entry if it does not exist already (NULL on error)
 * Note: only for DADs, i.e. the MAC layer uses 'ff:ff:ff:ff:ff:ff'
 */
struct IPv6_Host *create_dad_entry_ifnew(struct IPv6_Hosts_head *head,
                                                const struct timeval *tv,
                                                const u_int8_t ether_source[],
                                                const sfip_t *ip_src)
{
    return create_host_entry(head, tv, ether_source, ip_src);
}

/**
 * deletes an IPv6_Host entry from DAD
 */
void del_dad_entry(struct IPv6_Hosts_head *head,
                          struct IPv6_Host *ip)
{
    del_host_entry(head, ip);
}

/**
 * creates an IPv6_Host entry (or NULL on error)
 */
struct IPv6_Host *create_host_entry(struct IPv6_Hosts_head *head,
                                           const struct timeval *tv,
                                           const u_int8_t ether_source[],
                                           const sfip_t *ip_src)
{
    struct IPv6_Host *ip_entry = NULL;
    struct IPv6_Host *ip_dupl  = NULL;

    if (head->entry_limit && head->entry_limit <= head->entry_counter) {
        _dpd.logMsg("MAC Tree @ 0x%x is full with %d elements,"
                    " cannot add new entry\n",
                    head, head->entry_counter);
        return NULL;
    }

    if (!(ip_entry = (struct IPv6_Host *) calloc(1, sizeof (struct IPv6_Host)))) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "malloc failed in %s:%d\n", __FILE__, __LINE__););
        return NULL;
    }

    // get IP (link-local)
    if (sfip_set_ip(&ip_entry->ip, ip_src)) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "error in sfip_set_ip in %s:%d\n", __FILE__, __LINE__););
        free(ip_entry);
        return NULL;
    }
    // get MAC
    memcpy(&ip_entry->ether_source, ether_source, MAC_LENGTH);
    // get timestamp
    ip_entry->last_adv_ts = tv->tv_sec;

    // insert
    if ((ip_dupl = RB_INSERT(IPv6_Hosts_data, &head->data, ip_entry))) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                      "RB_INSERT failed in %s:%d\n\tnode %s/%s\n",
                      __FILE__, __LINE__,
                      pprint_mac(ip_dupl->ether_source),
                      sfip_to_str(&ip_dupl->ip)););
        return NULL;
    } else {
        head->entry_counter++;
        //DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RB_INSERT @ 0x%x, now %d entries\n", mac_head, mac_head->entry_counter););
        return ip_entry;
    }
}

/**
 * use MAC list to retrieve on IPv6_Host entry (or NULL on error)
 * i.e. search both layers
 *
 * FIXME: unused?
 */
struct IPv6_Host *get_machost_entry(struct MAC_Entry_head *head,
                                           const u_int8_t ether_source[],
                                           const sfip_t *ip_src)
{
    struct MAC_Entry *mac = get_mac_entry(head, ether_source);

    if (mac) return get_host_entry(mac->ips, ip_src);
    else     return NULL;
}

/**
 * retrieves an IPv6_Host entry (or NULL on error)
 */
struct IPv6_Host *get_host_entry(struct IPv6_Hosts_head *head,
                                        const sfip_t *ip_src)
{
    struct IPv6_Host ip_pivot;
    if (sfip_set_ip(&ip_pivot.ip, ip_src)) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "error in sfip_set_ip in %s:%d\n", __FILE__, __LINE__););
        return NULL;
    }
    return RB_FIND(IPv6_Hosts_data, &head->data, &ip_pivot);
}

/**
 * retrieves a MAC_List entry (or NULL on error)
 */
struct MAC_Entry *get_mac_entry(struct MAC_Entry_head *head,
                                       const u_int8_t ether_source[])
{
    struct MAC_Entry mac_pivot = {
        .mac = {ether_source[0], ether_source[1], ether_source[2],
                ether_source[3], ether_source[4], ether_source[5]}
    };
    return RB_FIND(MAC_Entry_data, &head->data, &mac_pivot);
}

/**
 * creates a MAC_List entry, including the IP-tree head
 * returns entry, or NULL on error
 */
struct MAC_Entry *create_mac_entry(struct MAC_Entry_head *head,
                                          const u_int8_t ether_source[])
{
    struct MAC_Entry       *new_mac = NULL;
    struct IPv6_Hosts_head *ip_head = NULL;

    if (!(new_mac = (struct MAC_Entry *) calloc(1, sizeof (struct MAC_Entry)))) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "malloc failed in %s:%d\n", __FILE__, __LINE__););
        return NULL;
    }
    if (!(ip_head = (struct IPv6_Hosts_head *) calloc(1, sizeof (struct IPv6_Hosts_head)))) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "malloc failed in %s:%d\n", __FILE__, __LINE__););
        free(new_mac);
        return NULL;
    }

    new_mac->ips = ip_head;
    RB_INIT(&new_mac->ips->data);
    memcpy(&new_mac->mac, ether_source, MAC_LENGTH);
    if (RB_INSERT(MAC_Entry_data, &head->data, new_mac)) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RB_INSERT failed in %s:%d\n", __FILE__, __LINE__););
        free(new_mac);
        free(ip_head);
        return NULL;
    } else {
        return new_mac;
    }
}

/**
 * Add a router to a sorted list.
 */
LISTOP_RET state_router_add(struct IPv6_Hosts_head *head,
                                   struct IPv6_Host **elem,
                                   const struct timeval* tv,
                                   const u_int8_t ether_source[],
                                   const sfip_t* ip_src,
                                   sfip_t* prefix,
                                   struct ICMPv6_RA* radv
                                   )
{
    LISTOP_RET rc;
    char old[64], new[64];

    rc = state_host_add(head, elem, tv, ether_source, ip_src);

    if (rc == LISTOP_ADDED) {
        // new router: add prefix & flags
        if (((*elem)->type.router.prefix = (sfip_t*) calloc(1, sizeof (sfip_t))))
            (*elem)->type.router.prefix = prefix;
        (*elem)->type.router.flags.all = radv->flags.all;
        (*elem)->type.router.lifetime  = radv->nd_ra_lifetime;
        return LISTOP_ADDED;
    } else if (rc == LISTOP_UPDATED) {
        // known router: verify prefix & flags

        // TODO: check if one router may announce multiple prefixes
        // the second cmp is a workaround because sfip_compare
        if (sfip_compare((*elem)->type.router.prefix, prefix) != SFIP_EQUAL
            || sfip_bits((*elem)->type.router.prefix) != sfip_bits(prefix)) {
            snprintf(old, sizeof(old), "%s/%d",
                     sfip_to_str((*elem)->type.router.prefix),
                     sfip_bits((*elem)->type.router.prefix));
            snprintf(new, sizeof(new), "%s/%d",
                     sfip_to_str(prefix),
                     sfip_bits(prefix));
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "announced router prefix changed "
                "from %s to %s\n", old, new););
            ALERT(SID_ICMP6_RA_PREFIX_CHANGED);
        }

        if ((*elem)->type.router.flags.all != radv->flags.all ||
            (*elem)->type.router.lifetime  != radv->nd_ra_lifetime
        ) {
            ALERT(SID_ICMP6_RA_FLAGS_CHANGED);
            // keep it simple and just update everything after alert
            (*elem)->type.router.flags.all = radv->flags.all;
            (*elem)->type.router.lifetime  = radv->nd_ra_lifetime;
        }
    }
    return rc;
}

/**
 * add host to state
 * ip_src is optional (if NULL, then package ip_src is used)
 */
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
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s new IPv6 host: %s / %s\n",
                      pprint_ts(p->pkt_header->ts.tv_sec),
                      pprint_mac(p->ether_header->ether_source),
                      sfip_to_str(target_ip)););
        if (context->config->host_whitelist
            && !RB_EMPTY(&context->config->host_whitelist->data)
            && !get_mac_entry(context->config->host_whitelist, p->ether_header->ether_source)) {
            ALERT(SID_ICMP6_INVALID_HOST_MAC);
        } else {
            ALERT(SID_ICMP6_ND_NEW_HOST);
        }
    } else if (rc == LISTOP_UPDATED) { // nothing
    } else { // (rc == LISTOP_ERROR)
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "IPv6 PP: cannot add state for IPv6 host %s / %s\n",
                      pprint_mac(p->ether_header->ether_source),
                      sfip_to_str(target_ip)););
    }
}

/**
 * Add a host to a sorted MAC/IP list. If entry exists then only update timestamp.
 *
 * Returns address of added host entry in *elem.
 */
LISTOP_RET state_host_add(struct IPv6_Hosts_head *head,
                                 struct IPv6_Host **elem,
                                 const struct timeval* tv,
                                 const u_int8_t ether_source[],
                                 const sfip_t* ip_src)
{

    /* MAC entry exists --> check if IP is already known */
    struct IPv6_Host *ip_entry = get_host_entry(head, ip_src);

    if (ip_entry) { // IP exists --> update timestamp and exit
        ip_entry->last_adv_ts = tv->tv_sec;
        *elem = ip_entry;
        return LISTOP_UPDATED;
    }

    /* else: either MAC existed without IP, or MAC was just created *
     * --> anyway, now create IPv6_Host                             */
    *elem = create_host_entry(head, tv, ether_source, ip_src);
    if (!*elem)
        return LISTOP_ERROR;
    else
        return LISTOP_ADDED;
}

/**
 * Auxillary function to print uniform lists of hosts and routers.
 */
void state_host_printlist(struct IPv6_Hosts_head *head)
{
    struct IPv6_Host *host;
    char routerinfo[128];

    RB_FOREACH(host, IPv6_Hosts_data, &head->data) {
        if (host->type.router.prefix && sfip_is_set(host->type.router.prefix)) {
        // for routers:
            snprintf(routerinfo, sizeof (routerinfo),
                     "\n\t-- prefix %s/%d, lifetime %d sec, flags %s%s%s, pref %s",
                     sfip_to_str(host->type.router.prefix),
                     sfip_bits(host->type.router.prefix),
                     host->type.router.lifetime,
                     host->type.router.flags.m ? "M" : "-",
                     host->type.router.flags.o ? "O" : "-",
                     host->type.router.flags.h ? "H" : "-",
                     (host->type.router.flags.prf == 0 ? "default" :
                         (host->type.router.flags.prf == 3 ? "low" :
                             (host->type.router.flags.prf == 1 ? "high" : "reserved")))
            );
        } else
            routerinfo[0] = '\0';

        _dpd.logMsg("MAC %s -- IP %s -- last seen: %s%s\n",
                    pprint_mac(host->ether_source),
                    sfip_to_str(&host->ip),
                    pprint_ts(host->last_adv_ts),
                    routerinfo);
    }
}

/**
 * Auxillary function to expire entries from state.
 * now is the current timestamp,
 * keep indicates the hold time, should come from config->keep_state
 *
 * returns number of entries after deletions
 */
u_int32_t state_host_expirelist(struct IPv6_Hosts_head *head, time_t now, time_t keep)
{
    struct IPv6_Host *var, *nxt;
    u_int32_t entries = 0;

    for (var = RB_MIN(IPv6_Hosts_data, &head->data); var != NULL; var = nxt) {
        nxt = RB_NEXT(IPv6_Hosts_data, &head->data, var);

        if (now - var->last_adv_ts > keep) { // expired
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s expire %s / %s after %d secs (leaves %d entries)\n",
                          pprint_ts(now),
                          pprint_mac(var->ether_source),
                          sfip_to_str(&var->ip),
                          now - var->last_adv_ts,
                          head->entry_counter - 1););
            del_host_entry(head, var);
        } else {
            entries++;
        }
    }
    return entries;
}

/**
 * Aux. function to get memory consumtion
 */
size_t state_host_memusage(struct IPv6_Hosts_head *head)
{
    struct IPv6_Host *var;
    size_t size = 0;

    size += sizeof(*head);
    RB_FOREACH(var, IPv6_Hosts_data, &head->data) {
        size += sizeof(*var);
        if (var->type.router.prefix)
            size += sizeof(*var->type.router.prefix);
    }
    return size;
}
