/*
 * spp_ipv6_data_mac.c
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of MAC addresses.
 * Currently a wrapper arround Snort's sfghash.
 *
 * A later optimization may replace some functions by macros, but during
 * development I keep them for better debugging, testing, and type checking.
 *
 */

#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_host.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Compare MAC addesses for equality.
 */
bool mac_eq(const MAC_t *a, const MAC_t *b)
{
    return (0 == mac_cmp(a, b));
}

/**
 * Compare MAC addesses.
 */
int mac_cmp(const MAC_t *a, const MAC_t *b)
{
    return memcmp(&a->mac, &b->mac, sizeof(a->mac));
}

/**
 * Copy MAC addesses
 */
void mac_cpy(MAC_t *dst, const MAC_t *src)
{
    memcpy(dst, src, sizeof(MAC_t));
}

/**
 * Parse a string MAC into binary data
 * no input checking, arguments have to be valid
 * 
 * MAC_node parameter is optional, if NULL then the static buffer is used.
 */
MAC_t *mac_parse(MAC_t *m, const char* string)
{
    static MAC_t node;
    
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
 * Transform int array to MAC_t
 * no input checking, arguments have to be valid
 * 
 * MAC_t parameter is optional, if NULL then the static buffer is used.
 */
MAC_t *mac_set(MAC_t *m, const u_int8_t ether_source[])
{
    static MAC_t node;
    if (!m)
        m = &node;
    m->mac[0] = ether_source[0];
    m->mac[1] = ether_source[1];
    m->mac[2] = ether_source[2];
    m->mac[3] = ether_source[3];
    m->mac[4] = ether_source[4];
    m->mac[5] = ether_source[5];
    return m;
}

/**
 * format MAC address (in static buffer).
 */
char *mac_str(const MAC_t *m)
{
    static char buf[MAC_STR_BUFLEN];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m->mac[0], m->mac[1],
             m->mac[2], m->mac[3],
             m->mac[4], m->mac[5]);
    return buf;
}

/**
 * create/alloc new MAC set
 */
MAC_set *macset_create(int count)
{
    MAC_set *s;
    if (!count) // set default
        count = 20;
    s = sfghash_new(count, sizeof(MAC_t), 0, NULL);
    return s;
}

/**
 * Delete and free macset.
 */
void macset_delete(MAC_set *s)
{
    HOST_t *data;
    SFGHASH_NODE *n;

    n = sfghash_findfirst(s);
    while (n) {
        data = n->data;
        if (data && data != HASHMARK) {
            host_free(data);
        }
        n = sfghash_findnext(s);
    }
    
    sfghash_delete(s);
}

/**
 * Add string MAC_node to a set.
 */
DATAOP_RET macset_add(MAC_set *s, const MAC_t *m)
{
    return sfghash_add(s, (MAC_t *) m, HASHMARK);
}

/**
 * Add string MAC to a set.
 */
DATAOP_RET macset_addstring(MAC_set *s, const char *mac)
{
    MAC_t *m;
    m = mac_parse(NULL, mac);
    return sfghash_add(s, m, HASHMARK);
}

/**
 * Add string MAC_node to a set.
 */
DATAOP_RET macset_add_data(MAC_set *s, const MAC_t *m, const void *data)
{
    return sfghash_add(s, (MAC_t *) m, (void *) data);
}


/**
 * add HOST_t to MAC_set
 */
DATAOP_RET macset_add_host(MAC_set *s, const void *data)
{
    HOST_t *h = (HOST_t *) data;
    if (!h)
        return DATA_ERROR;
    return macset_add_data(s, &h->mac, h);
}

/**
 * check if set contains MAC
 */
bool macset_contains(MAC_set *s, const MAC_t *m)
{
    return (NULL != sfghash_find(s, (MAC_t *)m));
}

/**
 * get set entry data
 */
void *macset_get(MAC_set *s, const MAC_t *m)
{
    return sfghash_find(s, (MAC_t *)m);
}

/**
 * test if set is empty
 */
bool macset_empty(MAC_set *s)
{
    return (macset_count(s) == 0);
}

/**
 * count set entries
 */
int macset_count(MAC_set *s)
{
    return sfghash_count(s);
}

/**
 * remove MAC from set
 */
DATAOP_RET macset_remove(MAC_set *s, const MAC_t *m)
{
    return sfghash_remove(s, (MAC_t *) m);
}
