/* 
 * File:   unittest_data_host.c
 * Author: mschuett
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/Basic.h"
#include "spp_ipv6_data_host.h"

// some random values for testing. hostdata has to be NULL terminated
// and have less or equal length than ipdata.
char *hostdata[] = {
    "ec:ac:24:70:4c:f6",
    "EC:AC:24:70:4C:F7",
    "Ec:aC:24:70:4c:F8",
    "38:45:63:f6:8e:83",
    "f7:d5:9c:38:8f:db",
    "bf:de:9e:0e:6e:eb",
    "b6:f5:bf:ff:c2:32",
    "83:23:3d:f2:17:31",
    "26:3e:f2:4e:0d:ff",
    "d4:fc:84:dc:81:a9",
    "d4:fc:84:dc:81:a9",
    "d4:fc:84:dc:81:a9",
    "d4:fc:84:dc:81:a9",
    "d4:fc:84:dc:81:a9",
    NULL
};

char *ipdata[] = {
    "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
    "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
    "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
    "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
    "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
    "0E51:A030:C113:3838:C080:DD09:4D6C:189D",
    "9af2:2354:ecd1:f412:b9e3:648C:519D:DDDF",
    "69df:0c97:aaff:ef86:7cc0:ede5:2a7b:6cc0",
    "4605:da5a:9f0f:8a36:f63a:e40a:1614:0554",
    "6956:2caa:6abf:f6b2:3c57:a99c:d88d:ff7d",
    "4a7d:e4d7:54ea:48ed:8467:6b59:3670:a941",
    "1d24:c623:219a:0aa1:7628:51ce:870a:898f",
    "5e0f:1e4b:e619:d99f:dd65:caf1:12a5:01fc",
    "8693:39c0:36de:d326:cb63:a585:c63e:2f04",
    NULL
};

/* a == b, using m and i; and a != c != d */
const MAC_t m = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
const IP_t i = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    };
const HOST_t a = {
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
const HOST_t b = {
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
const HOST_t c = {
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
const HOST_t d = {
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
 * CUnit Test Suite
 */

int init_suite(void) {
    return 0;
}

int clean_suite(void) {
    return 0;
}

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
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);
    
    s = hostset_create(0,0,0);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(5000,0,0);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(0,5000,0);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(0,0,5000);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(5000,5000,0);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(1, hostset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    hostset_delete(s);

    s = hostset_create(0,5000,5000);
    CU_ASSERT_PTR_NOT_NULL(s);
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
    CU_ASSERT_PTR_NOT_NULL(s);
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
    s = hostset_create(0,0,256);
    CU_ASSERT_PTR_NOT_NULL(s);
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
    CU_ASSERT_PTR_NOT_NULL(s);
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
    
    s = hostset_create(5,0,0);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_EQUAL(0, hostset_count(s));
    rc = hostset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = hostset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    CU_ASSERT_TRUE(hostset_contains(s, &a));
    CU_ASSERT_TRUE(hostset_contains(s, &b));
    CU_ASSERT_TRUE(hostset_contains(s, &c));
    CU_ASSERT_FALSE(hostset_contains(s, &d));

    hostset_delete(s);
}

void testHostset_get() {
    HOST_set *s;
    DATAOP_RET rc;
    HOST_t *p = NULL;
    
    s = hostset_create(5,0,0);
    CU_ASSERT_PTR_NOT_NULL(s);
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
    CU_ASSERT_PTR_NOT_NULL(s);
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

int main() {
    CU_pSuite pSuite = NULL;

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Add a suite to the registry */
    pSuite = CU_add_suite("unittest_data_host", init_suite, clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "testHost_eq",  testHost_eq))    ||
        (NULL == CU_add_test(pSuite, "testHost_str", testHost_str))   ||
        (NULL == CU_add_test(pSuite, "testHost_set", testHost_set))   ||
        (NULL == CU_add_test(pSuite, "testHostset_create",       testHostset_create))       ||
        (NULL == CU_add_test(pSuite, "testHostset_add",          testHostset_add))          ||
        (NULL == CU_add_test(pSuite, "testHostset_count",        testHostset_count))        ||
        (NULL == CU_add_test(pSuite, "testHostset_contains",     testHostset_contains))     ||
        (NULL == CU_add_test(pSuite, "testHostset_get",          testHostset_get))          ||
        (NULL == CU_add_test(pSuite, "testHostset_get_by_ipmac", testHostset_get_by_ipmac)) ||
        (NULL == CU_add_test(pSuite, "testHostset_remove",       testHostset_remove))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    
    /* Run all tests using the CUnit Basic interface */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}

