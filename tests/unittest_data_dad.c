/* 
 * File:   unittest_data_dad.c
 * Author: mschuett
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/Basic.h"
#include "spp_ipv6_data_structs.h"
#include "spp_ipv6_data_dad.h"

// h are 'normal' MAC/IP pairs;
// g has hosts with the same IP but all different MACs
#define EXAMPLE_LEN 10
static HOST_t h[EXAMPLE_LEN], g[EXAMPLE_LEN];

int testDAD_init_suite() {
    char *macdata[] = {
        "ec:ac:24:70:4c:f6", "EC:AC:24:70:4C:F7",
        "Ec:aC:24:70:4c:F8", "38:45:63:f6:8e:83",
        "f7:d5:9c:38:8f:db", "bf:de:9e:0e:6e:eb",
        "b6:f5:bf:ff:c2:32", "83:23:3d:f2:17:31",
        "26:3e:f2:4e:0d:ff", "d4:fc:84:dc:81:a9",
        NULL
    };
    char *ipdata[] = {
        "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4", "0E51:A030:C113:3838:C080:DD09:4D6C:189D",
        "9af2:2354:ecd1:f412:b9e3:648C:519D:DDDF", "69df:0c97:aaff:ef86:7cc0:ede5:2a7b:6cc0",
        "4605:da5a:9f0f:8a36:f63a:e40a:1614:0554", "6956:2caa:6abf:f6b2:3c57:a99c:d88d:ff7d",
        "4a7d:e4d7:54ea:48ed:8467:6b59:3670:a941", "1d24:c623:219a:0aa1:7628:51ce:870a:898f",
        "5e0f:1e4b:e619:d99f:dd65:caf1:12a5:01fc", "8693:39c0:36de:d326:cb63:a585:c63e:2f04",
        NULL
    };
    char *ipstr = "5338:41ab:64f7:a598:39b6:e0f8:5a6e:5ec8";
    IP_t ip;
    int i;
    
    ip_parse(&ip, ipstr);

    for (i = 0; i < EXAMPLE_LEN; i++) {
        host_set(&h[i], mac_parse(NULL, macdata[i]), ip_parse(NULL, ipdata[i]), 0);
    }
    for (i = 0; i < EXAMPLE_LEN; i++) {
        host_set(&g[i], mac_parse(NULL, macdata[i]), &ip, 0);
    }
    return 0;
}
    
/*
 * Tests for DAD functions
 */

void testDAD_create() {
    DAD_set *s;

    s = dad_create(0, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s->ip));
    CU_ASSERT_EQUAL(0, dad_count(s));
    dad_delete(s);

    s = dad_create(10, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s->ip));
    CU_ASSERT_EQUAL(0, dad_count(s));
    dad_delete(s);

    s = dad_create(10240, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s->ip));
    CU_ASSERT_EQUAL(0, dad_count(s));
    dad_delete(s);
}

void testDAD_add() {
    DAD_set *s;
    DATAOP_RET rc;
    
    s = dad_create(20, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, dad_count(s));
    
    rc = dad_add(s, &h[0]);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(1, dad_count(s));
    //dad_print_all(s);
    
    rc = dad_add(s, &g[0]);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(2, dad_count(s));

    dad_delete(s);
}

void testDAD_add_countlimit() {
    DAD_set *s;
    DATAOP_RET rc;
    
    s = dad_create(20, 2, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, dad_count(s));
    
    rc = dad_add(s, &h[0]);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(1, dad_count(s));
    //dad_print_all(s);
    
    rc = dad_add(s, &g[0]);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(2, dad_count(s));

    rc = dad_add(s, &h[1]);
    CU_ASSERT_EQUAL(rc, DATA_NOMEM);
    CU_ASSERT_EQUAL(2, dad_count(s));

    rc = dad_add(s, &g[1]);
    CU_ASSERT_EQUAL(rc, DATA_NOMEM);
    CU_ASSERT_EQUAL(2, dad_count(s));

    dad_delete(s);
}


void testDAD_add_memlimit() {
    DAD_set *s;
    DATAOP_RET rc;
    
    s = dad_create(20, 0, 100);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, dad_count(s));
    
    rc = dad_add(s, &h[0]);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(1, dad_count(s));
    
    rc = dad_add(s, &g[0]);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(2, dad_count(s));

    rc = dad_add(s, &h[1]);
    CU_ASSERT_EQUAL(rc, DATA_NOMEM);
    CU_ASSERT_EQUAL(2, dad_count(s));

    rc = dad_add(s, &g[1]);
    CU_ASSERT_EQUAL(rc, DATA_NOMEM);
    CU_ASSERT_EQUAL(2, dad_count(s));

    dad_delete(s);
}

void testDAD_addall() {
    DAD_set *s;
    DATAOP_RET rc;
    int i;
    
    s = dad_create(20, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, dad_count(s));
    
    for (i = 0; i < EXAMPLE_LEN; i++) {
        CU_ASSERT_EQUAL(2*i, dad_count(s));
        rc = dad_add(s, &h[i]);
        CU_ASSERT_EQUAL(rc, DATA_ADDED);
        CU_ASSERT_EQUAL(2*i+1, dad_count(s));
        rc = dad_add(s, &g[i]);
        CU_ASSERT_EQUAL(rc, DATA_ADDED);
        CU_ASSERT_EQUAL(2*i+2, dad_count(s));
    }
    CU_ASSERT_EQUAL(20, dad_count(s));

    //dad_print_all(s);
    dad_delete(s);
}

void testDAD_add_by_ipmac() {
    DAD_set *s;
    DATAOP_RET rc;
    int i;
    
    s = dad_create(20, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, dad_count(s));
    
    for (i = 0; i < EXAMPLE_LEN; i++) {
        rc = dad_add_by_ipmac(s, &h[i].ip, &h[i].mac, h[i].last_adv_ts);
        CU_ASSERT_EQUAL(rc, DATA_ADDED);
        rc = dad_add_by_ipmac(s, &g[i].ip, &g[i].mac, g[i].last_adv_ts);
        CU_ASSERT_EQUAL(rc, DATA_ADDED);
    }
    CU_ASSERT_EQUAL(20, dad_count(s));
    dad_delete(s);
}

void testDAD_remove() {
    DAD_set *s;
    DATAOP_RET rc;
    int i;
    
    s = dad_create(20, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, dad_count(s));
    
    for (i = 0; i < EXAMPLE_LEN; i++) {
        rc = dad_add(s, &h[i]);
        rc = dad_add(s, &g[i]);
    }
    CU_ASSERT_EQUAL_FATAL(20, dad_count(s));
    // set up complete
    
    rc = dad_remove(s, &h[1]);
    CU_ASSERT_EQUAL(rc, DATA_OK);

    rc = dad_remove(s, &h[2]);
    CU_ASSERT_EQUAL(rc, DATA_OK);

    rc = dad_remove(s, &g[1]);
    CU_ASSERT_EQUAL(rc, DATA_OK);

    rc = dad_remove(s, &g[2]);
    CU_ASSERT_EQUAL(rc, DATA_OK);
    CU_ASSERT_EQUAL(16, dad_count(s));

    rc = dad_remove(s, &g[2]);
    CU_ASSERT_EQUAL(rc, DATA_ERROR);
    CU_ASSERT_EQUAL(16, dad_count(s));

    dad_delete(s);
}


void testDAD_get() {
    DAD_set *s;
    DATAOP_RET rc;
    int i;
    HOST_t *ptr;
    
    s = dad_create(20, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    for (i = 0; i < EXAMPLE_LEN; i++) {
        rc = dad_add(s, &h[i]);
        rc = dad_add(s, &g[i]);
    }
    CU_ASSERT_EQUAL_FATAL(20, dad_count(s));
    // set up complete

    for (i = 0; i < EXAMPLE_LEN; i++) {
        ptr = dad_get(s, &h[i]);
        CU_ASSERT_TRUE(host_eq(ptr, &h[i]));
        CU_ASSERT_TRUE(dad_contains(s, &h[i]));
        ptr = dad_get(s, &g[i]);
        CU_ASSERT_TRUE(host_eq(ptr, &g[i]));
        CU_ASSERT_TRUE(dad_contains(s, &g[i]));
    }
    
    CU_ASSERT_TRUE(dad_contains(s, &h[2]));
    rc = dad_remove(s, &h[2]);
    CU_ASSERT_EQUAL(rc, DATA_OK);
    CU_ASSERT_FALSE(dad_contains(s, &h[2]));
    ptr = dad_get(s, &h[2]);
    CU_ASSERT_PTR_NULL(ptr);

    dad_delete(s);
}

