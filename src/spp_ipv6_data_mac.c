/*
 * spp_ipv6_data_mac.c
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of MAC addresses.
 * Currently a wrapper arround Snort's sfxhash.
 *
 */

#include "spp_ipv6_data_mac.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Compare MAC addesses
 */
int mac_cmp(MAC_node *a, MAC_node *b)
{
    return memcmp(&a->mac, &b->mac, sizeof(a->mac));
}

/**
 * Parse a string MAC into binary data
 * no input checking, arguments have to be valid
 * 
 * MAC_node parameter is optional, if NULL then the static buffer is used.
 */
MAC_node *mac_parse(const char* string, MAC_node *m)
{
    static MAC_node node;
    
    if (!m)
        m = &node;
    m->mac[0] = (u_int8_t) strtoul(&string[ 0], NULL, 16);
    m->mac[1] = (u_int8_t) strtoul(&string[ 3], NULL, 16);
    m->mac[2] = (u_int8_t) strtoul(&string[ 6], NULL, 16);
    m->mac[3] = (u_int8_t) strtoul(&string[ 9], NULL, 16);
    m->mac[4] = (u_int8_t) strtoul(&string[12], NULL, 16);
    m->mac[5] = (u_int8_t) strtoul(&string[15], NULL, 16);
    return m;
}

/**
 * Aux. function to format MAC address (in static buffer).
 */
char *mac_pprint(const MAC_node *m)
{
    static char buf[18];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m->mac[0], m->mac[1],
             m->mac[2], m->mac[3],
             m->mac[4], m->mac[5]);
    return buf;
}

MAC_set *macset_create(int count, int maxcount, int memsize)
{
    MAC_set *s;
    if (!count) // set default
        count = 20;
    s = sfxhash_new(count,
            sizeof(MAC_node),
            0,
            memsize,
            0, NULL, NULL, MACSET_RECYCLE);
    if (s) {
        sfxhash_splaymode(s, MACSET_SPLAY);
        sfxhash_set_max_nodes(s, maxcount);
    }
    return s;
}

/**
 * Add string MAC_node to a set.
 */
DATAOP_RET macset_add(MAC_set *s, MAC_node *m)
{
    return sfxhash_add(s, m, HASHMARK);
}

/**
 * Add string MAC to a set.
 */
DATAOP_RET macset_addstring(MAC_set *s, const char *mac)
{
    MAC_node *m;
    m = mac_parse(mac, NULL);
    return sfxhash_add(s, m, HASHMARK);
}

/**
 * check if set contains MAC
 */
bool macset_contains(MAC_set *s, MAC_node *m)
{
    MAC_node *k;
    k = sfxhash_find(s, m);
    if (!k)
        return false;
    else {
        // quick sanity check
        assert(k == HASHMARK);
        return true;
    }
}
