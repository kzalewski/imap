/* ========================================================================
 * Copyright 1988-2006 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 
 * ========================================================================
 */

/*
 * Program:	Operating-system dependent routines -- SVR4 version
 *
 * Author:	Mark Crispin
 *		Networks and Distributed Computing
 *		Computing & Communications
 *		University of Washington
 *		Administration Building, AG-44
 *		Seattle, WA  98195
 *		Internet: MRC@CAC.Washington.EDU
 *
 * Date:	10 April 1992
 * Last Edited:	20 December 2006
 */

#include <string.h>

#include <sys/types.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <utime.h>
#include <syslog.h>
#include <sys/file.h>
#include <ustat.h>


/* Many versions of SysV get this wrong */

#define setpgrp(a,b) Setpgrp(a,b)
int Setpgrp (int pid,int gid);


/* Different names, equivalent things in BSD and SysV */

/* L_SET is defined for some strange reason in <sys/file.h> on SVR4. */
#ifndef L_SET
#define L_SET SEEK_SET
#endif
#define L_INCR SEEK_CUR
#define L_XTND SEEK_END

#define direct dirent
#define random lrand48

#define utime portable_utime

long gethostid (void);
typedef int (*select_t) (struct direct *name);
typedef int (*compar_t) (void *d1,void *d2);
int scandir (char *dirname,struct direct ***namelist,select_t select,
	     compar_t compar);
int alphasort (void *d1,void *d2);


#include "env_unix.h"
#include "fs.h"
#include "ftl.h"
#include "nl.h"
#include "tcp.h"
#include "utime_port.h"
#include "flocksim.h"
