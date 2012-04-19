#! /bin/sh
#
# verify that the preprocessor's header files are in sync with snort release
#

snort_src_dir=/home/mschuett/ipv6/codebase/trunk/snort

for f in attribute_table_api.h \
bitop.h \
cpuclock.h \
idle_processing.h \
ipv6_port.h \
mempool.h \
obfuscation.h \
preprocids.h \
profiler.h \
segment_mem.h \
sfPolicy.h \
sfPolicyUserData.h \
sf_decompression.h \
sf_dynamic_common.h \
sf_dynamic_define.h \
sf_dynamic_engine.h \
sf_dynamic_meta.h \
sf_dynamic_preproc_lib.h \
sf_dynamic_preprocessor.h \
sf_ip.h \
sf_protocols.h \
sf_sdlist_types.h \
sf_snort_packet.h \
sf_snort_plugin_api.h \
sfcontrol.h \
sfhashfcn.h \
sfrt.h \
sfrt_dir.h \
sfrt_flat.h \
sfrt_flat_dir.h \
sfrt_trie.h \
snort_bounds.h \
snort_debug.h \
str_search.h \
stream_api.h; do
  cmp include/dynamic_preproc/$f ${snort_src_dir}/src/dynamic-preprocessors/include/$f
done

for f in sfcommon.h ssl.h; do
  cmp include/dynamic_preproc/$f ${snort_src_dir}/src/dynamic-preprocessors/libs/$f
done

for f in sf_types.h snort_debug.h; do
  cmp include/$f ${snort_src_dir}/src/$f
done

