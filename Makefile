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
MODOBJS     = nsradiusd.o

PROCS   = radiusd_procs.tcl

INSTALL += install-procs

include  $(NAVISERVER)/include/Makefile.module

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done


