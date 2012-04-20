/*
 * spp_ipv6_data_ip.c
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of IP addresses.
 *
 */

#include "spp_ipv6_data_ip.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Compare IP addesses
 */
int ip_cmp(IP_node *a, IP_node *b)
{
    return memcmp(&a->ip, &b->ip, sizeof(a->ip));
}

/**
 * Parse a string IP into binary data
 * no input and little output checking, arguments have to be valid
 * 
 * IP_node parameter is optional, if NULL then the static buffer is used.
 */
IP_node *ip_parse(const char* string, IP_node *m)
{
    static IP_node node;
    SFIP_RET status;

    if (!m)
        m = &node;
    status = sfip_pton(string, m);

    if (status != SFIP_SUCCESS)
        m = NULL;
    return m;
}

/**
 * Check if IP is a network/prefix.
 */
#define ip_isprefix(m) !( \
           ((sfip_family(m) == AF_INET6) && (sfip_bits((sfip_t*)m) == 128)) \
        || ((sfip_family(m) == AF_INET)  && (sfip_bits((sfip_t*)m) ==  32)) \
)

/**
 * Aux. function to format IP address (in static buffer).
 */
char *ip_pprint(const IP_node *m)
{
    if (ip_isprefix(m)) {
        static char buf[INET6_ADDRSTRLEN+5]; // add space for prefixlen
        snprintf(buf, sizeof(buf), "%s/%d",
                sfip_to_str(m), sfip_bits((sfip_t*) m));
        return buf;
    }
    else 
        return sfip_to_str(m);
}

IP_set *ipset_create(int count, int maxcount, int memsize)
{
    IP_set *s;
    if (!count) // set default
        count = 20;
    s = sfxhash_new(count,
            sizeof(IP_node),
            0,
            memsize,
            0, NULL, NULL, IPSET_RECYCLE);
    if (s) {
        sfxhash_splaymode(s, IPSET_SPLAY);
        sfxhash_set_max_nodes(s, maxcount);
    }
    return s;
}

/**
 * Add IP_node to a set.
 */
DATAOP_RET ipset_add(IP_set *s, IP_node *m)
{
    return sfxhash_add(s, m, HASHMARK);
}

/**
 * Add string IP to a set.
 */
DATAOP_RET ipset_addstring(IP_set *s, const char *mac)
{
    IP_node *m;
    m = ip_parse(mac, NULL);
    return sfxhash_add(s, m, HASHMARK);
}

/**
 * check if set contains IP
 */
bool ipset_contains(IP_set *s, IP_node *m)
{
    IP_node *k;
    k = sfxhash_find(s, m);
    if (!k)
        return false;
    else {
        // quick sanity check
        assert(k == HASHMARK);
        return true;
    }
}
