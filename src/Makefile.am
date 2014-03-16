## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

AM_CFLAGS=`pkg-config --cflags snort`

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_ipv6_preproc.la

libsf_ipv6_preproc_la_LDFLAGS = -export-dynamic

libsf_ipv6_preproc_la_SOURCES = sf_dynamic_preproc_lib.c sfPolicyUserData.c sf_ip.c spp_ipv6.c spp_ipv6_data_structs.c spp_ipv6_ruleopt.c
