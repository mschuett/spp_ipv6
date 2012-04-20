/* 
 * File:   test_data_structs.c
 * Author: mschuett
 *
 * Created on April 20, 2012, 2:01 PM
 */

#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_ip.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

// stub for util.c
// meaning SnortAlloc will crash in case of error, but good enough for a test tool
int _dpd;

/*
 * Test routines
 */
int test_mac()
{
    MAC_node node_m, node_n;
    MAC_node *m = &node_m, *n = &node_n, *o;
    MAC_set *s;
    
    int i, rc;
    char *c;
    char *macdata[] = {
        "ec:ac:24:70:4c:f6",
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
        NULL
    };
    printf("mac_parse\n");
    mac_parse("10:9b:7f:b1:ef:f7", m);
    mac_parse("10:9b:7f:b1:ef:f7", n);
    assert(!mac_cmp(m,n));
    mac_parse("00:9b:7f:b1:ef:f7", n);
    assert(mac_cmp(m,n));
    mac_parse("10:9b:7f:b1:ef:f6", n);
    assert(mac_cmp(m,n));
    
    printf("create macset\n");
    s = macset_create(0,0,0);
    assert(s);
    
    printf("fill macset\n");
    for (i = 0; macdata[i]; i++) {
        c = macdata[i];
        o = mac_parse(c, m);
        assert(m == o);
        rc = macset_add(s, m);
        assert(rc == DATA_ADDED);
    }

    printf("macset addstrings\n");
    for (i = 0; macdata[i]; i++) {
        c = macdata[i];
        assert(IS_MAC(c));
        rc = macset_addstring(s, c);
        assert(rc == DATA_EXISTS);
    }
    
    printf("macset addmacs\n");
    for (i = 0; macdata[i]; i++) {
        c = macdata[i];
        o = mac_parse(c, m);
        assert(m == o);
        rc = macset_add(s, m);
        assert(rc == DATA_EXISTS);
    }

    printf("macset_contains\n");
    assert(macset_contains(s, mac_parse("10:9b:7f:b1:ef:f7", NULL)));
    assert(!macset_contains(s, mac_parse("00:9b:7f:b1:ef:f7", NULL)));
    assert(!macset_contains(s, mac_parse("00:00:00:00:00:00", NULL)));
   
    printf("mac_pprint: '%s'\n", mac_pprint(m));
    printf("mac_pprint: '%s'\n", mac_pprint(n));

    return (EXIT_SUCCESS);
}

int test_ip()
{
    IP_node node_m, node_n;
    IP_node *m = &node_m, *n = &node_n, *o;
    IP_set *s;
    
    int i, rc;
    char *c;
    char *ipdata[] = {
        "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
        "0e51:a030:c113:3838:c080:dd09:4d6c:189d",
        "9af2:2354:ecd1:f412:b9e3:648c:519d:dddf",
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
        "2a01:8d53:900b:24fe::972f:3ecb",
        "2003:d730:c26d:17b4:8692:ff9a:da88:0000/69",
        "2a01:8d53:900b:d2ee:0000:0000:0000:0000/64",
        "2a01::/16",
        NULL
    };
    printf("ip_parse/ip_cmp\n");
    ip_parse("2003:d730:c26d:17b4:8692:ff9a:da88:c99f", m);
    ip_parse("2003:d730:c26d:17b4:8692:ff9a:da88:c99f", n);
    assert(!ip_cmp(m,n));
    ip_parse("1003:d730:c26d:17b4:8692:ff9a:da88:c99f", m);
    assert(ip_cmp(m,n));
    ip_parse("2003:d730:c26d:17b4:8692:ff9a:da88:c99e", m);
    assert(ip_cmp(m,n));
    
    printf("create ipset\n");
    s = ipset_create(0,0,0);
    assert(s);
    
    printf("fill ipset\n");
    for (i = 0; ipdata[i]; i++) {
        c = ipdata[i];
        o = ip_parse(c, m);
        assert(m == o);
        rc = ipset_add(s, m);
        assert(rc == DATA_ADDED);
    }

    printf("ipset addstrings\n");
    for (i = 0; ipdata[i]; i++) {
        c = ipdata[i];
        rc = ipset_addstring(s, c);
        assert(rc == DATA_EXISTS);
    }
    
    printf("ipset addips\n");
    for (i = 0; ipdata[i]; i++) {
        c = ipdata[i];
        o = ip_parse(c, m);
        assert(m == o);
        rc = ipset_add(s, m);
        assert(rc == DATA_EXISTS);
    }

    printf("ipset_contains\n");
    assert(ipset_contains(s, ip_parse("6b01:7257:7cf1:0896:a0d0:f130:c736:e0db", NULL)));
    assert(!ipset_contains(s, ip_parse("6b01:7257:7cf1:0896:a0d0:f130:c736:e0de", NULL)));
    assert(!ipset_contains(s, ip_parse("6b00:7257:7cf1:0896:a0d0:f130:c736:e0db", NULL)));
   
    printf("ip_pprint: '%s'\n", ip_pprint(m));
    printf("ip_pprint: '%s'\n", ip_pprint(n));

    return (EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
    return test_mac() || test_ip();
}
