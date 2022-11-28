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
 * Program:        XOAuth2 authenticator
 *
 * Author:        David Hedberg
 *
 * Based authenticators by:
 *                Mark Crispin
 *                Networks and Distributed Computing
 *                Computing & Communications
 *                University of Washington
 *                Administration Building, AG-44
 *                Seattle, WA  98195
 *                Internet: MRC@CAC.Washington.EDU
 */

#include <string.h>
#include "rfc822.h"

long auth_xoauth2_client(authchallenge_t challenger, authrespond_t responder,
                         char *service, NETMBX *mb, void *stream,
                         unsigned long *trial, char *user);
char *auth_xoauth2_server(authresponse_t responder, int argc, char *argv[]);

AUTHENTICATOR auth_oa2 = {
  AU_AUTHUSER | AU_HIDE,        /* allow authuser, hidden */
  "XOAUTH2",                    /* authenticator name */
  NIL,                          /* always valid */
  auth_xoauth2_client,          /* client method */
  auth_xoauth2_server,          /* server method */
  NIL                           /* next authenticator */
};

/* Client authenticator
 * Accepts: challenger function
 *            responder function
 *            SASL service name
 *            parsed network mailbox structure
 *            stream argument for functions
 *            pointer to current trial count
 *            returned user name
 * Returns: T if success, NIL otherwise
 */

long auth_xoauth2_client(authchallenge_t challenger, authrespond_t responder,
                         char *service, NETMBX *mb, void *stream,
                         unsigned long *trial, char *user)
{
  char *u, pwd[MAILTMPLEN], tmp[MAILTMPLEN];
  void *challenge;
  unsigned long clen;
  long ret = NIL;

  *trial = 65535;                /* never retry */

  if (challenge = (*challenger)(stream, &clen)) {
    fs_give ((void **) &challenge);
    if (clen) {                /* abort if challenge non-empty */
      mm_log ("Server bug: non-empty initial XOAUTH2 challenge",WARN);
      (*responder)(stream, NIL, 0);
      ret = LONGT;                /* will get a BAD response back */
    }
    pwd[0] = NIL;
    mm_login(mb, user, pwd, *trial);
    if (!user[0] || !pwd[0]) {        /* empty challenge */
      (*responder)(stream, NIL, 0);
      ret = LONGT;                /* will get a BAD response back */
    }
    else {
      unsigned long elen, rlen = strlen(user) + strlen(pwd) + 20;
      char *err, *response = (char *) fs_get(rlen + 1);

      sprintf(response, "user=%s\1auth=Bearer %s\1\1", user, pwd);

      if ((*responder)(stream, response, rlen)) {
        if (challenge = (*challenger)(stream, &clen)) {
          (*responder)(stream, "", 0);
          sprintf(tmp, "XOAUTH2 error: %.80s", challenge);
          mm_log(tmp, ERROR);
          fs_give((void **) &challenge);
        }
        else {
          ret = LONGT;
        }
      }

      memset(response, 0, rlen); /* erase credentials */
      fs_give((void **) &response);
    }
  }
  memset(pwd, 0, MAILTMPLEN);        /* erase credentials */
  return ret;
}

/* Server authenticator (NOOP)
 * Accepts: responder function
 *            argument count
 *            argument vector
 * Returns: Always returns NIL
 */

char *auth_xoauth2_server(authresponse_t responder, int argc, char *argv[])
{
  return NIL;
}
