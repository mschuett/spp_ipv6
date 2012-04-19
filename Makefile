
#### Compiler and tool definitions shared by all build targets #####
BASICOPTS = -fPIC -O1
CONFIGFLAGS = -DSF_WCHAR -DSUP_IP6 -DTARGET_BASED -DPERF_PROFILING -DSNORT_RELOAD -DNORMALIZER -DACTIVE_RESPONSE

# Define the target directories.
TARGETDIR = build
INSTALLFILENAME = lib_ipv6_preproc.so
INSTALLDIR ?= /usr/lib/snort/snort_dynamicpreprocessor

all: $(TARGETDIR)/lib_ipv6_preproc.so

# For development/debugging
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
	$(TARGETDIR)/spp_ipv6_data_structs.o \
	$(TARGETDIR)/sf_ip.o \
	$(TARGETDIR)/sfPolicyUserData.o \
	$(TARGETDIR)/sf_dynamic_preproc_lib.o
	

# Link or archive
SHAREDLIB_FLAGS = -shared 
$(TARGETDIR)/lib_ipv6_preproc.so: $(TARGETDIR) $(OBJS) $(DEPLIBS)
	$(LINK.c) -o $@ $(OBJS) $(SHAREDLIB_FLAGS) $(LDLIBS)

# Compile source files into .o files
$(TARGETDIR)/%.o: src/%.c
	$(COMPILE.c) -o $@ $<

# install
install: $(TARGETDIR)/lib_ipv6_preproc.so
	install $(TARGETDIR)/lib_ipv6_preproc.so $(INSTALLDIR)/$(INSTALLFILENAME)

uninstall:
	rm -f $(INSTALLDIR)/$(INSTALLFILENAME)

#### Clean target deletes all generated files ####
clean:
	rm -f \
		$(TARGETDIR)/spp_ipv6.o \
		$(TARGETDIR)/spp_ipv6_ruleopt.o \
		$(TARGETDIR)/spp_ipv6_data_structs.o \
		$(TARGETDIR)/lib_ipv6_preproc.so \
		$(TARGETDIR)/sf_ip.o \
		$(TARGETDIR)/sf_dynamic_preproc_lib.o \
		$(TARGETDIR)/sfPolicyUserData.o
	rm -f -r $(TARGETDIR)


# Create the target directory (if needed)
$(TARGETDIR):
	mkdir -p $(TARGETDIR)
