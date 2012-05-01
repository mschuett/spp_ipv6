/* 
 * File:   spp_ipv6_data_dad.h
 * Author: mschuett
 *
 * The DAD data set is somewhat special: because it is accessed by IP address
 * it cannot use the HOST_set type.
 * So it uses a 1st level IP_set, with every entry being a 2nd level MAC_set,
 * containing the HOST_t entries.
 * 
 * So we have no dedicated DAD_t or DAD_set, but still some special functions
 * to access this nested structures.
 * 
 * TODO:
 * The big problem with this approach: we lose the memory management features
 * of sfxhash. -- with these two layers we have to re-implement all entry
 * counting and expiring functions.
 */

#ifndef SPP_IPV6_DATA_DAD_H
#define	SPP_IPV6_DATA_DAD_H

#include <assert.h>
#include "spp_ipv6_data_structs.h"

#include "sf_dynamic_preprocessor.h"
extern DynamicPreprocessorData _dpd;

typedef struct _DAD_set {
    IP_set *ip;
    int    count;
    int    maxcount;
    size_t mem;
    size_t maxmem;
} DAD_set;


static inline int dad_count(DAD_set *s);

/**
 * create DAD state
 */
static inline DAD_set *dad_create(int count, int maxcount, int memsize)
{
    DAD_set *s;
    IP_set  *i;
    
    s = malloc(sizeof(DAD_set));
    if (!s)
        return NULL;
    i = ipset_create(count);
    if (!i) {
        free(s);
        return NULL;
    }
    
    s->ip       = i;
    s->count    = 0;
    s->mem      = 0;
    s->maxcount = maxcount;
    s->maxmem   = memsize;
    return s;
}

/**
 * delete DAD state
 */
static inline void dad_delete(DAD_set *s)
{
    ipset_delete(s->ip);
    free(s);
}

/**
 * allocate memory and add HOST_t to DAD state
 */
static inline DATAOP_RET dad_add(DAD_set *s, const HOST_t *h)
{
    bool new_macset = false;
    DATAOP_RET rc;
    MAC_set *p;

    assert(dad_count(s) == s->count);

    if ((s->maxcount && (s->count >= s->maxcount))
            || (s->maxmem && (s->mem >= s->maxmem)))
        return DATA_NOMEM;
            
    p = ipset_get(s->ip, &h->ip);
    if (!p) {
        p = macset_create(0);
        if (!p)
            return DATA_ERROR;
        
        // also add the macset to the ipset
        rc = ipset_add_data(s->ip, &h->ip, p);
        if (rc != DATA_OK) {
            macset_delete(p);
            return DATA_ERROR;
        }

        new_macset = true;
    }
    
    // now *p is our 2nd level MAC_set inside the 1st level IP_set s
    rc = macset_add_host(p, h);
    
    if (new_macset && rc != DATA_OK) {
        // in case of error: clean up
        ipset_remove(s->ip, &h->ip);
        return rc;
    }

    if (rc == DATA_OK) {
        s->count++;
        s->mem += sizeof(HOST_t) + (new_macset * sizeof(MAC_set));
    }
    
    assert(dad_count(s) == s->count);
    return rc;
}

/**
 * allocates new HOST_t and adds it to DAD state
 */
static inline DATAOP_RET dad_add_by_ipmac(DAD_set *s, const IP_t *i, const MAC_t *m, time_t ts)
{
    return dad_add(s, host_set(NULL, m, i, ts));
}


/**
 * remove HOST_t from DAD state
 */
static inline DATAOP_RET dad_remove(DAD_set *s, const HOST_t *h)
{
    DATAOP_RET rc;
    MAC_set *p;

    assert(dad_count(s) == s->count);

    p = ipset_get(s->ip, &h->ip);
    if (!p) {
        return DATA_ERROR;
    }
    
    // now *p is our 2nd level MAC_set
    rc = macset_remove(p, &h->mac);
    if (rc == DATA_OK) {
        s->count--;
        s->mem -= sizeof(HOST_t);
    }
    if (macset_empty(p)) {
        ipset_remove(s->ip, &h->ip);
        s->mem -= sizeof(MAC_set);
    }
    
    assert(dad_count(s) == s->count);

    return rc;
}

/**
 * count DAD entries
 */
static inline int dad_count(DAD_set *s)
{
    int c = 0;
    MAC_set *ms;
    SFGHASH_NODE *n;

    // the old way
    n = sfghash_findfirst(s->ip);
    while (n) {
        ms = n->data;
        if (ms) {
            c += macset_count(ms);
        }
        n = sfghash_findnext(s->ip);
    }
    
    return c;
}

/**
 * get DAD state
 */
static inline HOST_t *dad_get(DAD_set *s, const HOST_t *h)
{
    MAC_set *ms;
    HOST_t  *result;

    ms = ipset_get(s->ip, &h->ip);
    if (!ms)
        return NULL;
    result = macset_get(ms, &h->mac);
    return result;
}

/**
 * check DAD state existance
 */
static inline bool dad_contains(DAD_set *s, const HOST_t *h)
{
    return NULL != dad_get(s, h);
}

/**
 * print all DAD entries
 */
static inline void dad_print_all(DAD_set *s)
{
    SFGHASH_NODE *n, *o;
    MAC_set *ms;
   
    _dpd.logMsg("DAD set with %d entries:\n", dad_count(s));
    n = sfghash_findfirst(s->ip);
    while (n) {
        ms = n->data;
        o = sfghash_findfirst(ms);
        while (o) {
            HOST_t *host = o->data;
            _dpd.logMsg("%s @ %p\n", host_str(host), host);
            // assert(!host->type.router.prefix && host->type.dad.contacted == MAGICMARKER);
            o = sfghash_findnext(ms);
        }
        n = sfghash_findnext(s->ip);
    }
}

#endif	/* SPP_IPV6_DATA_DAD_H */
