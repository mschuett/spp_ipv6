/* 
 * File:   unittests.c
 * Author: mschuett
 * 
 * Execute all CUnit tests
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/Basic.h"

void test_data_common();
void test_ts_str();

void testMac_cmp();
void testMac_eq();
void testMac_cpy();
void testMac_IS_MAC();
void testMac_parse();
void testMac_str();
void testMac_set();
void testMacset_create();
void testMacset_count();
void testMacset_add();
void testMacset_addstring();

int testIp_init_suite(void);
void testIp_cmp();
void testIp_eq();
void testIp_cpy();
void testIp_parse();
void testIp_str();
void testIp_set();
void testIpset_create();
void testIpset_count();
void testIpset_add();
void testIpset_addstring();

void testHost_eq();
void testHost_str();
void testHost_set();
void testHostset_create();
void testHostset_add();
void testHostset_count();
void testHostset_contains();
void testHostset_get();
void testHostset_get_by_ipmac();
void testHostset_remove();

    
/*
 * CUnit Test Suite
 */

int init_suite(void) {
    return 0;
}

int clean_suite(void) {
    return 0;
}


int main() {
    CU_pSuite pSuite = NULL;

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Add a suite to the registry */
    pSuite = CU_add_suite("unittest_data_misc", NULL, NULL);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    /* Add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "test_data_common", test_data_common)) ||
        (NULL == CU_add_test(pSuite, "test_ts_str", test_ts_str))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add a suite to the registry */
    pSuite = CU_add_suite("unittest_data_mac", NULL, NULL);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "testMac_cmp",    testMac_cmp))    ||
        (NULL == CU_add_test(pSuite, "testMac_eq",     testMac_eq))     ||
        (NULL == CU_add_test(pSuite, "testMac_cpy",    testMac_cpy))    ||
        (NULL == CU_add_test(pSuite, "testMac_IS_MAC", testMac_IS_MAC)) ||
        (NULL == CU_add_test(pSuite, "testMac_parse",  testMac_parse))  ||
        (NULL == CU_add_test(pSuite, "testMac_str",    testMac_str))    ||
        (NULL == CU_add_test(pSuite, "testMac_set",    testMac_set))    ||
        (NULL == CU_add_test(pSuite, "testMacset_create",    testMacset_create))    ||
        (NULL == CU_add_test(pSuite, "testMacset_count",     testMacset_count))     ||
        (NULL == CU_add_test(pSuite, "testMacset_add",       testMacset_add))       ||
        (NULL == CU_add_test(pSuite, "testMacset_addstring", testMacset_addstring))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    
    /* Add a suite to the registry */
    pSuite = CU_add_suite("unittest_data_ip", testIp_init_suite, NULL);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "testIp_cmp",    testIp_cmp))    ||
        (NULL == CU_add_test(pSuite, "testIp_eq",     testIp_eq))     ||
        (NULL == CU_add_test(pSuite, "testIp_cpy",    testIp_cpy))    ||
        (NULL == CU_add_test(pSuite, "testIp_parse",  testIp_parse))  ||
        (NULL == CU_add_test(pSuite, "testIp_str",    testIp_str))    ||
        (NULL == CU_add_test(pSuite, "testIp_set",    testIp_set))    ||
        (NULL == CU_add_test(pSuite, "testIpset_create",    testIpset_create))    ||
        (NULL == CU_add_test(pSuite, "testIpset_count",     testIpset_count))     ||
        (NULL == CU_add_test(pSuite, "testIpset_add",       testIpset_add))       ||
        (NULL == CU_add_test(pSuite, "testIpset_addstring", testIpset_addstring))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add a suite to the registry */
    pSuite = CU_add_suite("unittest_data_host", NULL, NULL);
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
