// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA
//
// Copyright (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include "config.h"
#include "wdlog.h"
#include "wdsignals.h"

#ifdef USE_KEYRING
#include <sys/types.h>
extern "C" {
    #include <keyutils.h>
}
#endif

#define KEY_PREFIX "nuxwdog:"

static void echoOff(int fd)
{
    if (isatty(fd)) {
        struct termios tio;
        tcgetattr(fd, &tio);
        tio.c_lflag &= ~ECHO;
        tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

static void echoOn(int fd)
{
    if (isatty(fd)) {
        struct termios tio;
        tcgetattr(fd, &tio);
        tio.c_lflag |= ECHO;
        tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

/* Routines to access named password strings */

typedef struct pwdenc_s pwdenc_t;
struct pwdenc_s {
    int len;
    void *ptr;
};

typedef struct pwddef_s pwddef_t;
struct pwddef_s {
    struct pwddef_s *pwdnext;
    char *pwdname;
    pwdenc_t pwdvalue;
    int serial;
#ifdef USE_KEYRING
    key_serial_t pwdserial;
    long pwdlen;
#endif
};

static pwddef_t *pwdlist = 0;


/*
 * This code used to contain a poor man's cipher block chaining encryption
 * which was not secure in any way.  We have chosen to store the passwords in
 * the kernel keyring instead.  The function below is simply a passthrough.
 * At a later point, it might be replaced with SDR code.
 */
char *
wd_pwd_obscurify(char *src, char *dest, int len, int decrypt)
{
    snprintf(dest, len, "%s", src);
    return dest;
}


void
watchdog_pwd_encrypt(char *pwdvalue, pwdenc_t *pwdcrypt)
{
    if (pwdcrypt == NULL)
        return;

    memset((void *)pwdcrypt, 0, sizeof(pwdenc_t));

    if (!pwdvalue) {
        return;
    }

    int len = strlen(pwdvalue);
    {
        if ((pwdcrypt->ptr = (void *)malloc(len)) == NULL)
            return;
    
        pwdcrypt->len = len;
        wd_pwd_obscurify(pwdvalue, (char *)pwdcrypt->ptr, len, 0);
    }
}

char *
watchdog_pwd_decrypt(pwdenc_t *pwdcrypt)
{
    if (!pwdcrypt->ptr) {
    	return NULL;
    }
    {
        char *buf;
        if ((buf = (char *)malloc(pwdcrypt->len + 1)) == NULL)
            return NULL;
        wd_pwd_obscurify((char *)(pwdcrypt->ptr), buf, pwdcrypt->len, 1);
        buf[pwdcrypt->len] = 0;   // null-terminate
        return buf;
    }
}

void
watchdog_pwd_free(pwdenc_t *pwdcrypt)
{
    if (pwdcrypt) {
        if (pwdcrypt->ptr) {
            memset(pwdcrypt->ptr, 0, pwdcrypt->len);
            free(pwdcrypt->ptr);
        }
        memset((void *)pwdcrypt, 0, sizeof(pwdenc_t));
    }
}

#ifdef USE_KEYRING        
int
watchdog_pwd_lookup(char *pwdname, int serial, char **pwdvalue)
{
    pwddef_t *pwdp;
    long keysize;
    int ret;

    *pwdvalue = 0;

    watchdog_log(LOG_INFO, "Using keyring version of lookup %s\n", pwdname);

    for (pwdp = pwdlist; pwdp != NULL; pwdp = pwdp->pwdnext) {

        if (!strcmp(pwdname, pwdp->pwdname)) {
            
            //
            // if we're asking for a higher serial number than we have
            // then the password must be wrong - we need to fail the
            // lookup to cause a reprompt (or a failure if we cannot
            // prompt anymore due to loss of ther terminal).
            //
            if (serial > pwdp->serial) {
                //watchdog_log(LOG_INFO, "failing serial test serial: %d, pwdp->serial %d\n", serial, pwdp->serial);
                return 0;
            }

            *pwdvalue = (char *) malloc(pwdp->pwdlen + 1);
            keysize = keyctl_read(pwdp->pwdserial, (char *) *pwdvalue,
                pwdp->pwdlen);

            if (keysize == -1) {
                ret = errno;
                watchdog_log(LOG_ERR, "keyctl read failed  [%d][%s].\n", ret, strerror(ret));
                if (*pwdvalue) free(*pwdvalue);
                return 0;
            } else if (keysize != pwdp->pwdlen) {
                watchdog_log(LOG_ERR, "keyctl_read returned key with wrong size, "
                    "expect [%ld] got [%ld].\n", pwdp->pwdlen, keysize);
                return 0;
            }
            (*pwdvalue)[keysize] = '\0';
            return 1;
        }
    }

    return 0;
}
#else
 
int
watchdog_pwd_lookup(char *pwdname, int serial, char **pwdvalue)
{
    pwddef_t *pwdp;

    *pwdvalue = 0;

    for (pwdp = pwdlist; pwdp != NULL; pwdp = pwdp->pwdnext) {

        if (!strcmp(pwdname, pwdp->pwdname)) {
            
            //
            // if we're asking for a higher serial number than we have
            // then the password must be wrong - we need to fail the
            // lookup to cause a reprompt (or a failure if we cannot
            // prompt anymore due to loss of ther terminal).
            //
            if (serial > pwdp->serial)
                return 0;

            *pwdvalue = watchdog_pwd_decrypt(&pwdp->pwdvalue);
            return 1;
        }
    }

    return 0;
}

#endif

#ifdef USE_KEYRING
int watchdog_pwd_save(char *pwdname, int serial, char *pwdvalue)
{
    pwddef_t *pwdp;
    int rv = 0;

    watchdog_log(LOG_INFO, "Using keyring version of save %s\n", pwdname);

    if (strlen(pwdvalue) == 0) {
       watchdog_log(LOG_INFO, "password invalid. length must be greater than 0\n");
       return 0;
    }

    for (pwdp = pwdlist; pwdp != NULL; pwdp = pwdp->pwdnext) {
        if (!strcmp(pwdname, pwdp->pwdname)) {

            /*
             * Already have this password saved, so server must be
             * reprompting.  Replace the old value with the new value.
             */
            char *keyname = (char *) malloc(strlen(pwdname) + strlen(KEY_PREFIX));
            sprintf(keyname, "%s%s", KEY_PREFIX, pwdname);
            pwdp->pwdserial = add_key("user", keyname, (void *) pwdvalue,
                strlen(pwdvalue), KEY_SPEC_PROCESS_KEYRING);

            if (keyname) free(keyname);

            if (pwdp->pwdserial == -1) {
                rv = errno;
                watchdog_log(LOG_ERR, "add key failed [%d][%s].\n", rv, strerror(rv));
                return 0;
            }
            pwdp->pwdlen = strlen(pwdvalue);
            pwdp->serial = serial;
            return 1;
        }
    }
    if ((pwdp = (pwddef_t *)malloc(sizeof(pwddef_t))) == NULL)
        return 0;

    pwdp->pwdname = strdup(pwdname);
    pwdp->serial = serial;

    char *keyname = (char *) malloc(strlen(pwdname) + strlen(KEY_PREFIX));
    sprintf(keyname, "%s%s", KEY_PREFIX, pwdname);
    pwdp->pwdserial = add_key("user", keyname, (void *) pwdvalue,
        strlen(pwdvalue), KEY_SPEC_PROCESS_KEYRING);
    if (pwdp->pwdserial == -1) {
        rv = errno;
        watchdog_log(LOG_ERR, "add key failed [%d][%s].\n", rv, strerror(rv));
        if (pwdp->pwdname) free(pwdp->pwdname);
        free(pwdp);
    } else {
        pwdp->pwdnext = pwdlist;
        pwdlist = pwdp;
        pwdp->pwdlen = strlen(pwdvalue);
        rv = 1;
    }
    if (keyname) free(keyname);
    return rv;
}

#else

int
watchdog_pwd_save(char *pwdname, int serial, char *pwdvalue)
{
    pwddef_t *pwdp;
    int rv = 0;

    for (pwdp = pwdlist; pwdp != NULL; pwdp = pwdp->pwdnext) {

        if (!strcmp(pwdname, pwdp->pwdname)) {
            
            /*
             * Already have this password saved, so server must be
             * reprompting.  Replace the old value with the new value.
             */

            watchdog_pwd_free(&pwdp->pwdvalue);
            watchdog_pwd_encrypt(pwdvalue, &pwdp->pwdvalue);
            pwdp->serial = serial;
            return 1;
        }
    }

    if ((pwdp = (pwddef_t *)malloc(sizeof(pwddef_t))) == NULL)
        return 0;

    pwdp->pwdname = strdup(pwdname);
    pwdp->serial = serial;

    watchdog_pwd_encrypt(pwdvalue, &pwdp->pwdvalue);
    if (pwdp->pwdvalue.len) {
        pwdp->pwdnext = pwdlist;
        pwdlist = pwdp;
        rv = 1;
    } else {
        /* watchdog_pwd_encrypt failed */

        free(pwdp);
        rv = 0;
    }
    return rv;
}
#endif

/*
 * is systemd running
 */
bool
check_systemd_running ()
{
  struct stat a, b;

  /* We simply test whether the systemd cgroup hierarchy is
   * mounted */

  return (lstat("/sys/fs/cgroup", &a) == 0)
     && (lstat("/sys/fs/cgroup/systemd", &b) == 0)
     && (a.st_dev != b.st_dev);

}

static bool
watchdog_get_passwd_systemd(const char *prompt, char *input, const int capacity)
{
    char *cmd, *ret;
    FILE *ask_pass_fp = NULL;
    bool retval = false;

    /* temporarily disable SIGCHLD handler */
    disable_sigchld_for_one_signal();

    cmd = ret = NULL;
    if (asprintf(&cmd, "systemd-ask-password \"%s\"", prompt) >= 0) {
        ask_pass_fp = popen (cmd, "re");
        free (cmd);
    }

    if (ask_pass_fp) {
        ret = fgets(input, capacity, ask_pass_fp);
        pclose(ask_pass_fp);
    }

    if (ret) {
        int len = strlen(input);
        if (input[len - 1] == '\n') input[len - 1] = '\0';
        return true;
    }
    return false;
}

int
watchdog_pwd_prompt(const char *prompt, int serial, char **pwdvalue)
{
    char phrase[256];
    char *cp;
    int infd = fileno(stdin);
    int isTTY = isatty(infd);
    int plen;

    char *started_by_systemd = getenv("STARTED_BY_SYSTEMD");

    if (started_by_systemd) {
        if (!check_systemd_running()) {
            fprintf(stderr,
                "STARTED_BY_SYSTEMD set indicating that nuxwdog has been started by systemd, but "
                "systemd is not running.");
            return -1;
        }

        char pvalue[256];
        pvalue[0] = '\0'; 
        if (watchdog_get_passwd_systemd(prompt, pvalue, 256)) {
            *pwdvalue = strdup(pvalue);
            return 0;
        }
        return -1;
    }

    /* Turn off buffering to avoid leaving password in I/O buffer */
    setbuf(stdin, NULL);

    /* Prompt for password */
    if (isTTY) {
        if (serial > 0)
            fprintf(stdout, "Password incorrect. Please try again.\n");
        fprintf(stdout, "%s", prompt);
        echoOff(infd);
    } else {
        /*
         * Since stdin is not a tty, fail if the server asks
         * for the same password.  The password is invalid, and it's
         * unlikely that a non-tty stdin is going to have the valid
         * one.
         */
        if (watchdog_pwd_lookup((char *)prompt, serial, pwdvalue)) {
            if (pwdvalue && *pwdvalue) {
                free((void *)(*pwdvalue));
            }
            return -2;
        }
    }

    /* Return error if EOF */
    if (feof(stdin)) {
        if (isTTY) {
            echoOn(infd);
        }
        return -1;
    }

    cp = fgets(phrase, sizeof(phrase), stdin);

    /* EOF is more likely to be seen here */
    if (cp == NULL) {
        if (isTTY) {
            echoOn(infd);
        }
        return -1;
    }

    if (isTTY) {
        fprintf(stdout, "\n");
        echoOn(infd);
    }

    /* stomp on newline */
    plen = strlen(phrase);
    if (plen > 0) {
        phrase[--plen] = 0;
    }

    *pwdvalue = strdup(phrase);

    /* Clear password from local buffer */
    memset((void *)phrase, 0, sizeof(phrase));

    return 0;
}
