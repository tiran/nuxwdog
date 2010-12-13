# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# Copyright (C) 2009 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

all-local:
	perl Makefile.PL INSTALLDIRS=vendor && $(MAKE) -f Makefile.real all
check-local:
	$(MAKE) -f Makefile.real test
clean-local:
	$(MAKE) -f Makefile.real clean
     
install-data-local:
	$(MAKE) -f Makefile.real install
install-exec-local:
	$(MAKE) -f Makefile.real install 
uninstall-local:
	$(MAKE) -f Makefile.real uninstall
     
# Distribute files from here.
EXTRA_DIST = Nuxwdogclient.xs fallback/const-xs.inc \
	fallback/const-c.inc const-xs.inc \
	typemap t/Nuxwdogclient.t \
	README  Changes lib/Nuxwdogclient.pm \
	MANIFEST ppport.h Makefile.PL \
	const-c.inc

