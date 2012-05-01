/* 
 * File:   unittest_data_ip.c
 * Author: mschuett
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/Basic.h"
#include "spp_ipv6_data_ip.h"


static char *ipdata[] = {
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
    "e4b8:49bf:c446:61d1:be0e:9c2c:576c:5569",
    "8c15:aa3e:fe29:02f4:3b26:e0cc:e11b:841e",
    "8ec7:35c2:42cf:3807:76fe:5559:3416:0159",
    "9343:d8c4:5312:b33c:e122:9ef1:495c:3219",
    "50c3:42cc:1ae4:232e:2f65:2688:185a:e358",
    "f268:1e93:8152:330d:af0c:739d:a7cc:7c32",
    "4f8b:17ea:ba51:9125:c6a1:1926:0e97:ebf7",
    "71ac:7e51:df32:a7c0:2e1e:4e72:1c1c:b1fe",
    "08f2:4b6b:19ec:0134:70f3:e535:30eb:2abf",
    "72e5:1837:4ed4:55b9:ab1d:fd72:5f5a:619f",
    "9da0:1246:e942:b4d8:815f:5b9c:a602:4ceb",
    "6b01:7257:7cf1:0896:a0d0:f130:c736:e0db",
    "5338:41ab:64f7:a598:39b6:e0f8:5a6e:5ec8",
    "629d:d9fe:4a47:3513:86c1:bc3d:38c3:0aa8",
    "caa0:301b:1c87:b030:7dc8:4938:db56:ddc4",
    "eb41:18ee:1ba3:91ea:cf72:19d9:5f5e:f72b",
    "2003:d730:c26d:17b4:8692:ff9a:da88:c99f",
    "2003:d730:c26d:17b4:8692:ff9a:da88:c9",
    "2a01:8d53:900b:24fe::972f:3ecb",
    "2003:d730:c26d:17b4:8692:ff9a:da88:0000/96",
    "2a01:8d53:900b:d2ee:0000:0000:0000:0000/64",
    "2a01::/16",
    "::1",
    "::",
    NULL
};

/*
 * CUnit Test Suite
 */

static IP_t a, b, c, d, e, f;
static const IP_t i = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    };
static const sfip_t sfip_i = {
        .family = AF_INET6,
        .bits = 128,
        .ip.u6_addr8 = {0x20, 0x3, 0xd7, 0x30, 0xc2, 0x6d, 0x17, 0xb4,
                0x86, 0x92, 0xff, 0x9a, 0xda, 0x88, 0xc9, 0x9a}
    };
static const char *str_i = "2003:d730:c26d:17b4:8692:ff9a:da88:c99a";

    
int testIp_init_suite(void) {
    ip_parse(&a, "2003:d730:c26d:17b4:8692:ff9a:da88:c99a");
    ip_parse(&b, "2003:d730:c26d:17b4:8692:ff9a:da88:c99a");
    ip_parse(&c, "2003:d730:c26d:17b4:8692:ff9a:da88:c990");
    ip_parse(&d, "2003:d730:c26d:17b4:8692:ff9a:da88:c991");
    ip_parse(&e, "2003:d730:c26d:17b4:8692:ff9a:da88:c992");
    ip_parse(&f, "2003:d730:c26d:17b4:8692:ff9a:da88:c993");
    return 0;
}

/*
 * Tests for IP_t and IP_set
 */

void testIp_cmp() {
    CU_ASSERT(ip_cmp(&i, &sfip_i) == 0);

    CU_ASSERT(ip_cmp(&a, &b) == 0);
    CU_ASSERT(ip_cmp(&a, &c) > 0);
    CU_ASSERT(ip_cmp(&c, &a) < 0);
}

void testIp_eq() {
    CU_ASSERT_TRUE(ip_eq(&i, &sfip_i));
    
    CU_ASSERT_TRUE(ip_eq(&a, &b));
    CU_ASSERT_TRUE(ip_eq(&b, &a));
    CU_ASSERT_FALSE(ip_eq(&a, &c));
    CU_ASSERT_FALSE(ip_eq(&c, &a));
}

void testIp_cpy() {
    IP_t d;
    
    ip_cpy(&d, &a);
    CU_ASSERT_TRUE(ip_eq(&a, &d));
    ip_cpy(&d, &c);
    CU_ASSERT_FALSE(ip_eq(&a, &d));
    CU_ASSERT_TRUE(ip_eq(&c, &d));
}

void testIp_parse() {
    int j;
    IP_t d;

    ip_parse(&d, str_i);
    CU_ASSERT_TRUE(ip_eq(&i, &d));
    CU_ASSERT_TRUE(ip_eq(&i, ip_parse(NULL, str_i)));

    CU_ASSERT_STRING_EQUAL(str_i, ip_str(ip_parse(NULL, str_i)));

    for (j = 0; ipdata[j]; j++) {
        CU_ASSERT_PTR_NOT_NULL(ip_parse(NULL, ipdata[j]));
    }
    
    // non_ipdata[]
    CU_ASSERT_PTR_NULL(ip_parse(NULL, "ffe5:1838::2472::3ae6:a228:12b4"));
    CU_ASSERT_PTR_NULL(ip_parse(NULL, "0e51:a030:c113:3838:c080:dd09:4d6c:189g"));
    CU_ASSERT_PTR_NULL(ip_parse(NULL, "9af2:2354:ecd1:f412:b9e3:648c:519d:dddf1"));
    CU_ASSERT_PTR_NULL(ip_parse(NULL, "a69df:0c97:aaff:ef86:7cc0:ede5:2a7b:6cc0"));
    CU_ASSERT_PTR_NULL(ip_parse(NULL, "4605da5a9f0f8a36f63ae40a16140554"));
    CU_ASSERT_PTR_NULL(ip_parse(NULL, "2a01:8d53:900b:d2ee:0000:0000:0000:0000/129"));
}

void testIp_str() {
    int j;

    CU_ASSERT_STRING_EQUAL(str_i, ip_str(&i));

    for (j = 0; j <= 26; j++) {
        IP_t *parsed_ip;
        
        // convert input to lower case
        char buf[IP_STR_BUFLEN];
        int k;
        for (k = 0; k < IP_STR_BUFLEN; k++) {
            buf[k] = tolower(ipdata[j][k]);
        }

        parsed_ip = ip_parse(NULL, ipdata[j]);
        CU_ASSERT_STRING_EQUAL(buf, ip_str(parsed_ip));
    }
}

void testIp_set() {
    IP_t d;
    IP_t *e = NULL;

    CU_ASSERT_PTR_NOT_NULL(ip_set(&d, &sfip_i));
    CU_ASSERT_STRING_EQUAL(str_i, ip_str(&d));

    e = ip_set(NULL, &sfip_i);
    CU_ASSERT_PTR_NOT_NULL(e);
    CU_ASSERT_PTR_NOT_EQUAL(&d, e)
    CU_ASSERT_STRING_EQUAL(str_i, ip_str(&d));
    
    CU_ASSERT_TRUE(ip_eq(&d, e));
    CU_ASSERT_TRUE(ip_eq(&d, &i));
    CU_ASSERT_TRUE(ip_eq(e, &i));
}

void testIpset_create() {
    IP_set *s;
    DATAOP_RET rc;
    
    s = ipset_create(0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &i);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    ipset_delete(s);
    
    s = ipset_create(1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &i);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    ipset_delete(s);

    s = ipset_create(5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &i);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    ipset_delete(s);

    s = ipset_create(5000);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &i);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    ipset_delete(s);

    s = ipset_create(50000);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &i);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    ipset_delete(s);
}

void testIpset_count() {
    IP_set *s = ipset_create(0);
    
    CU_ASSERT_EQUAL(0, ipset_count(s));
    CU_ASSERT_TRUE(ipset_empty(s));
    ipset_add(s, &i);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_FALSE(ipset_empty(s));
    ipset_remove(s, &i);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    CU_ASSERT_TRUE(ipset_empty(s));
    
    ipset_delete(s);
}

void testIpset_add() {
    IP_set *s;
    DATAOP_RET rc;
    
    // no limit by entry count
    s = ipset_create(2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &a);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);

    rc = ipset_add(s, &b);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_EXISTS);

    rc = ipset_add(s, &c);
    CU_ASSERT_EQUAL(2, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = ipset_add(s, &d);
    CU_ASSERT_EQUAL(3, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = ipset_add(s, &e);
    CU_ASSERT_EQUAL(4, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = ipset_add(s, &f);
    CU_ASSERT_EQUAL(5, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    //ipset_print_all(s, "Test set");
    ipset_delete(s);
}

void testIpset_addstring() {
    int j;
    IP_set *s;
    DATAOP_RET rc;
    
    s = ipset_create(25);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);

    rc = ipset_addstring(s, str_i);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(1, ipset_count(s));
    
    for (j = 0; ipdata[j]; j++) {
        rc = ipset_addstring(s, ipdata[j]);
        CU_ASSERT_EQUAL(rc, DATA_ADDED);
    }
    ipset_delete(s);
}

void testIpset_remove() {
    IP_set *s;
    DATAOP_RET rc;
    
    s = ipset_create(5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = ipset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = ipset_add(s, &d);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(3, ipset_count(s));

    rc = ipset_remove(s, &a);
    CU_ASSERT_EQUAL(2, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_OK);

    rc = ipset_remove(s, &a);
    CU_ASSERT_EQUAL(2, ipset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ERROR);

    ipset_delete(s);
}

void testIpset_contains() {
    IP_set *s;
    DATAOP_RET rc;
    
    s = ipset_create(5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, ipset_count(s));
    rc = ipset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = ipset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    CU_ASSERT_TRUE(ipset_contains(s, &a));
    CU_ASSERT_TRUE(ipset_contains(s, &b));
    CU_ASSERT_TRUE(ipset_contains(s, &c));
    CU_ASSERT_FALSE(ipset_contains(s, &d));

    ipset_delete(s);
}

