/* 
 * File:   unittest_data_host.c
 * Author: mschuett
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/Basic.h"
#include "spp_ipv6_data_host.h"

/* a == b, using m and i; and a != c != d */
static const MAC_t m = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
static const IP_t i = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    };
static const HOST_t a = {
    .mac = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
    .ip  = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    },
    .last_adv_ts = 0,
    .type.dad.noprefix = NULL,
    .type.dad.contacted = 0
};
static const HOST_t b = {
    .mac = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
    .ip  = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    },
    .last_adv_ts = 0,
    .type.dad.noprefix = NULL,
    .type.dad.contacted = 0
};
static const HOST_t c = {
    .mac = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}},
    .ip  = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    },
    .last_adv_ts = 0,
    .type.dad.noprefix = NULL,
    .type.dad.contacted = 0
};
static const HOST_t d = {
    .mac = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd}},
    .ip  = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    },
    .last_adv_ts = 0,
    .type.dad.noprefix = NULL,
    .type.dad.contacted = 0
};

/*
 * Tests for HOST_t and HOST_set
 */

void testHost_eq() {
    CU_ASSERT_TRUE(host_eq(&a, &b));
    CU_ASSERT_TRUE(host_eq(&b, &a));
    CU_ASSERT_FALSE(host_eq(&a, &c));
    CU_ASSERT_FALSE(host_eq(&c, &a));
}

void testHost_str() {
    char *should = "ff:ff:ff:ff:ff:ff -- 2003:d730:c26d:17b4:8692:ff9a:da88:c99a -- last seen: unknown";
    char *is;
    
    is = host_str(&a);
    CU_ASSERT_STRING_EQUAL(is, should);
    
}

void testHost_set() {
    HOST_t h;
    HOST_t *p, *q;

    p = host_set(&h, &m, &i, 0);
    CU_ASSERT_PTR_EQUAL(&h, p);
            
    q = host_set(NULL, &m, &i, 123);
    CU_ASSERT_PTR_NOT_NULL(q);
    CU_ASSERT_PTR_NOT_EQUAL(&h, q);
    
    CU_ASSERT_TRUE(host_eq(&a, &h));
    CU_ASSERT_TRUE(host_eq(&a, q));
    CU_ASSERT_TRUE(host_eq(&b, q));
}

void testHostset_create() {
    HOST_set *s;
    DATAOP_RET rc;
    
    s = hostset_create(0,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);
    
    s = hostset_create(0,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(5000,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(0,5000,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(0,0,5000);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(5000,5000,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(0,5000,5000);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);
}

void testHostset_count() {
    HOST_set *s = hostset_create(0,0,0);
    
    CU_ASSERT_EQUAL(0, hostset_count(s));
    CU_ASSERT_TRUE(hostset_empty(s));
    hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_FALSE(hostset_empty(s));
    hostset_remove(s, &a);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    CU_ASSERT_TRUE(hostset_empty(s));
    
    hostset_delete(s);
}

void testHostset_add() {
    HOST_set *s;
    DATAOP_RET rc;
    
    // limit by entry count
    s = hostset_create(4,2,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);

    rc = hostset_add(s, &b);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_EXISTS);

    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(2, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &d);
    CU_ASSERT_EQUAL(2, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_NOMEM);
    hostset_delete(s);
    
    // limit by memory usage
    // not a good test, because it depends on the implementation and possibly even memory layout
    s = hostset_create(0,0,756);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &b);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_EXISTS);
    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(2, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &d);
    CU_ASSERT_EQUAL(2, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_NOMEM);
    hostset_delete(s);
}

void testHostset_remove() {
    HOST_set *s;
    DATAOP_RET rc;
    
    s = hostset_create(5,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &d);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(3, hostset_count(s));

    rc = hostset_remove(s, &a);
    CU_ASSERT_EQUAL(2, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_OK);

    rc = hostset_remove(s, &a);
    CU_ASSERT_EQUAL(2, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ERROR);

    hostset_delete(s);
}

void testHostset_contains() {
    HOST_set *s;
    DATAOP_RET rc;
    HOST_t *p = NULL;
    
    s = hostset_create(5,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    CU_ASSERT_TRUE(hostset_contains(s, &a, 0));
    CU_ASSERT_TRUE(hostset_contains(s, &b, 0));
    CU_ASSERT_TRUE(hostset_contains(s, &c, 0));
    CU_ASSERT_FALSE(hostset_contains(s, &d, 0));

    CU_ASSERT_PTR_NULL(p);
    p = hostset_get(s, &b);
    CU_ASSERT_PTR_NOT_NULL(p);
    CU_ASSERT_EQUAL(p->last_adv_ts, 0);

    CU_ASSERT_TRUE(hostset_contains(s, &a, 1234567890));
    CU_ASSERT_TRUE(hostset_contains(s, &b, 1234567890));
    CU_ASSERT_TRUE(hostset_contains(s, &c, 1234567890));
    CU_ASSERT_FALSE(hostset_contains(s, &d, 1234567890));
    
    CU_ASSERT_TRUE(hostset_contains(s, &b, 1234567890));

    hostset_delete(s);
}

void testHostset_get() {
    HOST_set *s;
    DATAOP_RET rc;
    HOST_t *p = NULL;
    
    s = hostset_create(5,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    CU_ASSERT_PTR_NULL(p);
    p = hostset_get(s, &b);
    CU_ASSERT_PTR_NOT_NULL(p);
    CU_ASSERT_TRUE(host_eq(p, &a));

    p = hostset_get(s, &d);
    CU_ASSERT_PTR_NULL(p);

    hostset_delete(s);
}

void testHostset_get_by_ipmac() {
    HOST_set *s;
    DATAOP_RET rc;
    HOST_t *p = NULL;
    MAC_t n = {{ 0xaa, 0xff, 0xff, 0xff, 0xff, 0xff}};
    
    s = hostset_create(5,0,0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    CU_ASSERT_PTR_NULL(p);
    p = hostset_get_by_ipmac(s, &m, &i);
    CU_ASSERT_PTR_NOT_NULL(p);
    CU_ASSERT_TRUE(host_eq(p, &a));

    p = hostset_get_by_ipmac(s, &n, &i);
    CU_ASSERT_PTR_NULL(p);

    hostset_delete(s);
}
