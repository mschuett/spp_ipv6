/* 
 * File:   unittest_data_mac.c
 * Author: mschuett
 * 
 * Unit tests of MAC_t, MAC_set and the timestamp functions
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/Basic.h"
#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_time.h"

// some random values for testing. macdata has to be NULL terminated
// and have less or equal length than ipdata.
char *macdata[] = {
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
    "39:9f:2c:e6:26:b3",
    "64:7d:22:ee:b1:82",
    "14:a2:18:0d:f2:c4",
    "e3:c9:9f:06:10:02",
    "43:55:7b:ae:a2:09",
    "e0:01:0c:78:31:0a",
    "19:d9:a3:25:ee:e3",
    "e5:6d:9f:1e:ae:07",
    "bf:ad:66:a9:29:c5",
    "2f:bd:69:19:3c:84",
    "12:10:5a:05:b5:7e",
    "55:1e:c4:48:27:c8",
    "0d:36:73:87:2a:8e",
    "b1:de:6a:42:07:6f",
    "97:60:6b:22:0c:ff",
    "29:98:ef:14:00:9c",
    "10:9b:7f:b1:ef:f7",
    "ff:ff:ff:ff:ff:ff",
    NULL
};

char *no_macdata[] = {
    "eg:ac:24:70:4c:f6",
    "ec:ac:24:70:4c:f",
    "ec:ac:24:70:4c:f61",
    "ecac24704cf6",
    "ec-ac-24-70-4c-f6",
    NULL
};

/*
 * Some tests for basic definitions and the time stamp aux fct.
 */

void test_data_common() {
    CU_ASSERT_EQUAL(DATA_ADDED, DATA_OK);

    CU_ASSERT_EQUAL(DATA_ADDED, SFXHASH_OK);
    CU_ASSERT_EQUAL(DATA_OK,    SFXHASH_OK);
    CU_ASSERT_EQUAL(DATA_ADDED, SFGHASH_OK);
    CU_ASSERT_EQUAL(DATA_OK,    SFGHASH_OK);

    CU_ASSERT_EQUAL(DATA_NOMEM, SFXHASH_NOMEM);
    CU_ASSERT_EQUAL(DATA_NOMEM, SFGHASH_NOMEM);
    CU_ASSERT_EQUAL(DATA_EXISTS, SFXHASH_INTABLE);
    CU_ASSERT_EQUAL(DATA_EXISTS, SFGHASH_INTABLE);
    
    CU_ASSERT_EQUAL(DATA_ADDED, 0);
    CU_ASSERT_TRUE(SFXHASH_ERR < 0);
    CU_ASSERT_TRUE(DATA_ERROR < 0);
}

void test_ts_str() {
    /* bad tests because ts_str uses localtime instead of gmttime */
    CU_ASSERT_STRING_EQUAL(ts_str(0), "unknown");
    CU_ASSERT_STRING_EQUAL(ts_str(1), "1970-01-01 01:00:01");
    CU_ASSERT_STRING_EQUAL(ts_str(1234567890), "2009-02-14 00:31:30");
    CU_ASSERT_STRING_EQUAL(ts_str(1335000000), "2012-04-21 11:20:00");
}

/*
 * Tests for MAC_t and MAC_set
 */

void testMac_cmp() {
    MAC_t a = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    MAC_t b = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    MAC_t c = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}};
    CU_ASSERT(mac_cmp(&a, &b) == 0);
    CU_ASSERT(mac_cmp(&a, &c) > 0);
    CU_ASSERT(mac_cmp(&c, &a) < 0);
}

void testMac_eq() {
    MAC_t a = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    MAC_t b = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    MAC_t c = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}};
    CU_ASSERT_TRUE(mac_eq(&a, &b));
    CU_ASSERT_TRUE(mac_eq(&b, &a));
    CU_ASSERT_FALSE(mac_eq(&a, &c));
    CU_ASSERT_FALSE(mac_eq(&c, &a));
}

void testMac_IS_MAC() {
    int j;
    for (j = 0; macdata[j]; j++) {
        CU_ASSERT_TRUE(IS_MAC(macdata[j]));
    }
    for (j = 0; no_macdata[j]; j++) {
        CU_ASSERT_FALSE(IS_MAC(no_macdata[j]));
    }
    CU_ASSERT_FALSE(IS_MAC((char *)NULL));
}

void testMac_cpy() {
    MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    MAC_t b = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    MAC_t c = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    
    CU_ASSERT_TRUE(mac_eq(&b, &c));
    mac_cpy(&c, &a);
    CU_ASSERT_FALSE(mac_eq(&b, &c));
    CU_ASSERT_TRUE(mac_eq(&a, &c));
}

void testMac_parse() {
    int j;
    MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    char *str_a = "12:34:56:78:90:ab";

    for (j = 0; macdata[j]; j++) {
        CU_ASSERT_PTR_NOT_NULL(mac_parse(NULL, macdata[j]));
    }
    
    CU_ASSERT_TRUE(mac_eq(mac_parse(NULL, str_a), &a));
}

void testMac_str() {
    int j;
    MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    char *str_a = "12:34:56:78:90:ab";

    CU_ASSERT_STRING_EQUAL(str_a, mac_str(&a));

    for (j = 0; macdata[j]; j++) {
        MAC_t *parsed_mac;
        
        // convert input to lower case
        char buf[MAC_STR_BUFLEN];
        int k;
        for (k = 0; k < MAC_STR_BUFLEN; k++) {
            buf[k] = tolower(macdata[j][k]);
        }

        parsed_mac = mac_parse(NULL, macdata[j]);
        CU_ASSERT_STRING_EQUAL(buf, mac_str(parsed_mac));
    }
}

void testMac_set() {
    char *str_a = "12:34:56:78:90:ab";
    u_int8_t raw[] =  { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab};
    MAC_t    a     = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    MAC_t    b;
    MAC_t *c;

    CU_ASSERT_PTR_NOT_NULL(mac_set(&b, raw));
    CU_ASSERT_STRING_EQUAL(str_a, mac_str(&b));

    c = mac_set(NULL, raw);
    CU_ASSERT_PTR_NOT_NULL(c);
    CU_ASSERT_STRING_EQUAL(str_a, mac_str(c));
    
    CU_ASSERT_TRUE(mac_eq(&a, &b));
    CU_ASSERT_TRUE(mac_eq(&a, c));
    CU_ASSERT_TRUE(mac_eq(&b, c));
}

void testMacset_create() {
    const MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xaa}};
    MAC_set *s;
    DATAOP_RET rc;
    
    s = macset_create(0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    macset_delete(s);

    s = macset_create(1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    macset_delete(s);

    s = macset_create(5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    macset_delete(s);

    s = macset_create(5000);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    macset_delete(s);

    s = macset_create(5000000);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    macset_delete(s);
}

void testMacset_count() {
    MAC_t    a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    MAC_set *s = macset_create(5);
    
    CU_ASSERT_EQUAL(0, macset_count(s));
    CU_ASSERT_TRUE(macset_empty(s));
    macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_FALSE(macset_empty(s));
    macset_remove(s, &a);
    CU_ASSERT_EQUAL(0, macset_count(s));
    CU_ASSERT_TRUE(macset_empty(s));
    
    macset_delete(s);
}

void testMacset_add() {
    const MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xaa}};
    const MAC_t b = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    const MAC_t c = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xac}};
    const MAC_t d = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xad}};
    const MAC_t e = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xae}};
    MAC_set *s;
    DATAOP_RET rc;
    
    // no limit by entry count
    s = macset_create(2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);

    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(1, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_EXISTS);

    rc = macset_add(s, &b);
    CU_ASSERT_EQUAL(2, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = macset_add(s, &c);
    CU_ASSERT_EQUAL(3, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = macset_add(s, &d);
    CU_ASSERT_EQUAL(4, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = macset_add(s, &e);
    CU_ASSERT_EQUAL(5, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    macset_delete(s);
}

void testMacset_addstring() {
    int j;
    char *str_a = "12:34:56:78:90:ab";
    MAC_set *s;
    DATAOP_RET rc;
    
    s = macset_create(25);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);

    rc = macset_addstring(s, str_a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(1, macset_count(s));
    
    for (j = 0; macdata[j]; j++) {
        rc = macset_addstring(s, macdata[j]);
        CU_ASSERT_EQUAL(rc, DATA_ADDED);
    }
    //macset_print_all(s, "Test set");
    macset_delete(s);
}

void testMacset_remove() {
    const MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xaa}};
    const MAC_t b = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    const MAC_t c = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xac}};
    MAC_set *s;
    DATAOP_RET rc;
    
    s = macset_create(5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = macset_add(s, &b);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = macset_add(s, &c);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    CU_ASSERT_EQUAL(3, macset_count(s));

    rc = macset_remove(s, &a);
    CU_ASSERT_EQUAL(2, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_OK);

    rc = macset_remove(s, &a);
    CU_ASSERT_EQUAL(2, macset_count(s));
    CU_ASSERT_EQUAL(rc, DATA_ERROR);

    macset_delete(s);
}

void testMacset_contains() {
    const MAC_t a = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xaa}};
    const MAC_t b = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};
    const MAC_t c = {{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xac}};
    MAC_set *s;
    DATAOP_RET rc;
    
    s = macset_create(5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);
    CU_ASSERT_EQUAL(0, macset_count(s));
    rc = macset_add(s, &a);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    rc = macset_add(s, &b);
    CU_ASSERT_EQUAL(rc, DATA_ADDED);
    
    CU_ASSERT_TRUE(macset_contains(s, &a));
    CU_ASSERT_TRUE(macset_contains(s, &b));
    CU_ASSERT_FALSE(macset_contains(s, &c));

    macset_delete(s);
}

