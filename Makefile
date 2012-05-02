#### Compiler and tool definitions shared by all build targets #####
BASICOPTS = -fPIC -O1
CONFIGFLAGS = -DSF_WCHAR -DSUP_IP6 -DTARGET_BASED -DPERF_PROFILING -DSNORT_RELOAD -DNORMALIZER -DACTIVE_RESPONSE -DMODULUS_HASH

# Define the target directories.
TARGETDIR = build
TESTDIR = tests
INSTALLFILENAME = lib_ipv6_preproc.so
INSTALLDIR ?= /usr/lib/snort/snort_dynamicpreprocessor

all: $(TARGETDIR)/lib_ipv6_preproc.so

#### For development/debugging
debug: CONFIGFLAGS += -g3 -gdwarf-2 -Wall -DDEBUG -DDEBUG_MSGS

debug: all

CFLAGS = $(BASICOPTS)
CPPFLAGS = \
	-Iinclude \
	-Iinclude/daq \
	-Iinclude/dynamic_preproc \
	-DINLINE=inline \
	 $(CONFIGFLAGS)
OBJS =  \
	$(TARGETDIR)/spp_ipv6.o \
	$(TARGETDIR)/spp_ipv6_ruleopt.o \
	$(TARGETDIR)/spp_ipv6_data_mac.o \
	$(TARGETDIR)/spp_ipv6_data_ip.o \
	$(TARGETDIR)/spp_ipv6_data_host.o \
	$(TARGETDIR)/spp_ipv6_data_time.o \
	$(TARGETDIR)/sf_ip.o \
	$(TARGETDIR)/sfPolicyUserData.o \
	$(TARGETDIR)/sfxhash.o \
	$(TARGETDIR)/sfghash.o \
	$(TARGETDIR)/sfmemcap.o \
	$(TARGETDIR)/sfhashfcn.o \
	$(TARGETDIR)/sfprimetable.o \
	$(TARGETDIR)/sf_dynamic_preproc_lib.o \
	$(TARGETDIR)/debug.o \
	$(TARGETDIR)/util.o

UNITTESTOBJS =  \
	$(TESTDIR)/unittest_data_mac.o \
	$(TESTDIR)/unittest_data_ip.o \
	$(TESTDIR)/unittest_data_host.o \
	$(TESTDIR)/unittest_data_dad.o \
	$(TESTDIR)/unittests.o \
	$(OBJS)
UNITTESTLDLIBS = -lm -lcunit

#### normal plugin .so
# Link or archive
SHAREDLIB_FLAGS = -shared 
$(TARGETDIR)/lib_ipv6_preproc.so: $(TARGETDIR) $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(SHAREDLIB_FLAGS)

# Create the target/build directory
$(TARGETDIR):
	mkdir -p $(TARGETDIR)

# Compile source files into .o files
$(TARGETDIR)/%.o: src/%.c
	$(COMPILE.c) -o $@ $<

#### install/uninstall
install: $(TARGETDIR)/lib_ipv6_preproc.so
	install $(TARGETDIR)/lib_ipv6_preproc.so $(INSTALLDIR)/$(INSTALLFILENAME)

uninstall:
	rm -f $(INSTALLDIR)/$(INSTALLFILENAME)

#### CUnit tests
cunit: CONFIGFLAGS += -Isrc

cunit: $(TARGETDIR) $(TESTDIR)/unittests $(UNITTESTOBJS)

# Compile source files into .o files
$(TESTDIR)/%.o: $(TESTDIR)/%.c
	$(COMPILE.c) -o $@ $<

$(TESTDIR)/unittests: $(UNITTESTOBJS)
	$(LINK.c) -o $@ $(UNITTESTOBJS) $(UNITTESTLDLIBS)

#### Clean target deletes all generated files ####
clean:
	rm -f $(OBJS) $(UNITTESTOBJS) $(TESTDIR)/unittests
	rm -f -r $(TARGETDIR)
