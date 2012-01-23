
#### Compiler and tool definitions shared by all build targets #####
CC = gcc
BASICOPTS = -g -fPIC -O1 -Wall
CONFIGFLAGS = -DSF_WCHAR -DSUP_IP6 -DTARGET_BASED -DPERF_PROFILING -DSNORT_RELOAD -DNORMALIZER -DACTIVE_RESPONSE

# Define the target directories.
TARGETDIR=build

all: $(TARGETDIR)/spp_ipv6.so

CFLAGS = $(BASICOPTS)
CPPFLAGS = \
	-Iinclude \
	-Iinclude/daq \
	-Iinclude/dynamic_preproc \
	-DINLINE=inline \
	 $(CONFIGFLAGS)
OBJS =  \
	$(TARGETDIR)/spp_ipv6.o \
	$(TARGETDIR)/sf_ip.o \
	$(TARGETDIR)/sfPolicyUserData.o \
	$(TARGETDIR)/sf_dynamic_preproc_lib.o
	

# Link or archive
SHAREDLIB_FLAGS = -shared 
$(TARGETDIR)/spp_ipv6.so: $(TARGETDIR) $(OBJS) $(DEPLIBS)
	$(LINK.c) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJS) $(SHAREDLIB_FLAGS) $(LDLIBS)


# Compile source files into .o files
$(TARGETDIR)/%.o: src/%.c
	$(COMPILE.c) $(CFLAGS) $(CPPFLAGS) -o $@ $<

#### Clean target deletes all generated files ####
clean:
	rm -f \
		$(TARGETDIR)/spp_ipv6.so \
		$(TARGETDIR)/spp_ipv6.o \
		$(TARGETDIR)/sf_ip.o \
		$(TARGETDIR)/sf_dynamic_preproc_lib.o \
		$(TARGETDIR)/sfPolicyUserData.o
	rm -f -r $(TARGETDIR)


# Create the target directory (if needed)
$(TARGETDIR):
	mkdir -p $(TARGETDIR)


# Enable dependency checking
.KEEP_STATE:
.KEEP_STATE_FILE:.make.state.$(TARGETDIR)

