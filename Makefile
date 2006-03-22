ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsradiusd.so

#
# Objects to build.
#
OBJS     = nsradiusd.o

PROCS   = radiusd_procs.tcl

INSTALL += install-procs

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done

include  $(NAVISERVER)/include/Makefile.module

