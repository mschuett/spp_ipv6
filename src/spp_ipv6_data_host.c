/*
 * spp_ipv6_data_host.c
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of HOST addresses.
 * Currently a wrapper arround Snort's sfxhash.
 * 
 */

#include "spp_ipv6_data_host.h"
#include <assert.h>

#include "sf_dynamic_preprocessor.h"
extern DynamicPreprocessorData _dpd;

/**
 * Compare HOSTs for equality
 * TODO: see whether a host_cmp would be needed/useful.
 */
bool host_eq(const HOST_t *a, const HOST_t *b)
{
    return mac_eq(&a->mac, &b->mac) && ip_eq(&a->ip, &b->ip);
}

/**
 * Aux. function to format HOST address (in static buffer).
 */
char *host_str(const HOST_t *host)
{
    static char buf[HOST_STR_BUFLEN];
    char routerinfo[ROUTER_STR_BUFLEN];
    
    if (host->type.router.prefix && sfip_is_set(host->type.router.prefix)) {
        // for routers:
        snprintf(routerinfo, sizeof(routerinfo),
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

    snprintf(buf, sizeof(buf),
            "%s -- %s -- last seen: %s%s",
            mac_str(&host->mac),
            ip_str(&host->ip),
            ts_str(host->last_adv_ts),
            routerinfo);
    return buf;
}

/**
 * Aux. function to print all hosts in set.
 */
void hostset_print_all(HOST_set *s)
{
    HOST_t *host;
    SFXHASH_NODE *n;
   
    _dpd.logMsg("Hostset with %d entries:\n", hostset_count(s));
    n = sfxhash_findfirst(s);
    while (n) {
        host = n->data;
        _dpd.logMsg("%s\n", host_str(host));
        assert(host->type.router.prefix || host->type.dad.contacted == MAGICMARKER);
        
        n = sfxhash_findnext(s);
    }
}

/**
 * Set host data.
 * If *h is NULL, then use static buffer.
 */
HOST_t *host_set(HOST_t *h, const MAC_t *m, const IP_t *i, time_t t)
{
    static HOST_t node;
    if (!h)
        h = &node;
    // necessary in order to use HOST_t as a hash key,
    // otherwise the struct padding may contain arbitrary data
    bzero(h, sizeof(*h));
    
    ip_cpy(&h->ip, i);
    mac_cpy(&h->mac, m);
    h->last_adv_ts = t;
    
    // for debugging
    h->type.dad.contacted = MAGICMARKER;

    return h;
}

/**
 * Add router data to host.
 */
void host_setrouterdata(HOST_t *h, u_int8_t ra_flags, u_int16_t ra_lifetime, sfip_t* prefix)
{
    assert(h);

    h->type.router.flags.all = ra_flags;
    h->type.router.lifetime  = ra_lifetime;
    h->type.router.prefix    = prefix;
}

/**
 * free HOST
 */
void host_free(HOST_t *h)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "host_free: %p\n", h););
    if (h && h->type.router.prefix)
        sfip_free(h->type.router.prefix);
    free(h);
}

/**
 * Create a hostset
 */
HOST_set *hostset_create(int count, int maxcount, int memsize)
{
    HOST_set *s;
    if (!count) // set default
        count = 100;
    s = sfxhash_new(count,
            member_size(HOST_t, mac) + member_size(HOST_t, ip),
            sizeof(HOST_t),    // determines whether sfxhash will alloc memory for us
            memsize,
            0, NULL,
            hostset_userfree, HOSTSET_RECYCLE);
    if (s) {
        sfxhash_splaymode(s, HOSTSET_SPLAY);
        sfxhash_set_max_nodes(s, maxcount);
    }
    return s;
}

/**
 * Delete and free hostset.
 */
void hostset_delete(HOST_set *s)
{
    sfxhash_delete(s);
}

/**
 * allocate/copy new HOST_t and add to set.
 */
DATAOP_RET hostset_add(HOST_set *s, const HOST_t *h)
{
    DATAOP_RET rc;
    HOST_t *newentry;
    IP_t *newprefix;
    
    if (!h)
        return DATA_ERROR;

    assert(sfip_bits((IP_t *) &h->ip) == 128);
    /* important: the HOST_t is alloc'd by sfxhash_add,
     * but we have to alloc and copy the prefix ourselves */
    if (h->type.router.prefix) {
        newprefix = malloc(sizeof(IP_t));
        if (!newprefix)
            return DATA_NOMEM;
        ip_cpy(newprefix, h->type.router.prefix);
    }
        
    rc = sfxhash_add(s, (HOST_t *) h, (HOST_t *) h);
    
    if (h->type.router.prefix) {
        if (rc != DATA_ADDED) { // clean up
            free(newprefix);
        } else {  // fix prefix ptr
            newentry = sfxhash_lru(s);
            assert(host_eq(newentry, h));
            newentry->type.router.prefix = newprefix;
        }
    }
    return rc;
}

/**
 * get HOST from set
 */
HOST_t *hostset_get(HOST_set *s, const HOST_t *h)
{
    return sfxhash_find(s, (HOST_t *) h);
}

/**
 * find HOST from set by IP/MAC addr
 */
HOST_t *hostset_get_by_ipmac(HOST_set *s, const MAC_t *m, const IP_t *i)
{
    HOST_t pivot;
    host_set(&pivot, m, i, 0);
    return hostset_get(s, &pivot);
}


/**
 * check if set contains HOST,
 * just to provide same API as other data structs
 * 
 * if update_ts != 0 then update host's last_adv_ts
 */
bool hostset_contains(HOST_set *s, const HOST_t *h, time_t update_ts)
{
    HOST_t *node;
    
    node = hostset_get(s, h);
    if (!node)
        return false;
    if (update_ts)
        node->last_adv_ts = update_ts;
    return true;
}

/**
 * remove HOST from set
 */
int hostset_remove(HOST_set *s, const HOST_t *h)
{
    
    return sfxhash_remove(s, (HOST_t *) h);
}

/**
 * number of entries in hostset
 */
int hostset_count(HOST_set *s)
{
    return sfxhash_count(s);
}

/**
 * number of entries in hostset
 */
bool hostset_empty(HOST_set *s)
{
    return (0 == hostset_count(s));
}

/**
 * Aux. function to free an entry when removing from hostset.
 * The data is freed'd by sfxhash itself, we _only_ have to free
 * any additional references inside, i.e. the prefix for routers.
 */
int hostset_userfree(void *key, void *data)
{
    HOST_t *h = (HOST_t*) data;
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
            "hostset_userfree: %p with prefix %p\n",
            data, h->type.router.prefix););
    sfip_free(h->type.router.prefix);
 
    return 0;
}