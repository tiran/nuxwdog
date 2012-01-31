/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or
 * modify it under the same terms as Perl itself.
 * 
 * Copyright (C) 2009 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <nspr4/prtypes.h>

#include "ppport.h"

#include "../../../src/com/redhat/nuxwdog/WatchdogClient.h"

#include "const-c.inc"

MODULE = Nuxwdogclient		PACKAGE = Nuxwdogclient		

INCLUDE: const-xs.inc

PRStatus
call_WatchdogClient_init()

PRStatus
call_WatchdogClient_sendEndInit(numProcs)
        int numProcs

char *
call_WatchdogClient_getPassword(prompt, serial)
        char * prompt
        int serial

PRStatus
call_WatchdogClient_printMessage(msg)
        char * msg
