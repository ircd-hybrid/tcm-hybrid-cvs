/* Beginning of major overhaul 9/3/01 */

/* $Id: main.c,v 1.121 2002/06/24 00:40:21 db Exp $ */

#include "setup.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "event.h"
#include "userlist.h"
#include "bothunt.h"
#include "modules.h"
#include "stdcmds.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"
#include "parse.h"
#include "hash.h"
#include "logging.h"
#include "actions.h"
#include "handler.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

struct s_testline testlines;
time_t current_time;

/* total memory xmalloc'd */
unsigned long totalmem;
/* number of xmallocations */
unsigned long numalloc;
/* numer of xfrees */
unsigned long numfree;

#ifdef DEBUGMODE
void write_debug();
#endif

static void init_debug(int sig);
static void handle_sighup(int sig);

#ifdef HAVE_SETRLIMIT
static void setup_corefile(void);
#endif

/*
 * main()
 *   Parameters:
 *     argc - Count of command line arguments
 *     argv - List of command line arguments
 *   Returns: When the program dies.
 *   PDL:
 *  
 *  tcm only accepts one argument now, the name of a tcm.cf file, then
 *  set up assorted things: random numbers, handlers for seg faults and timers,
 *  Attach tcm to the server, sign her on to IRC, join her up
 *  to the channel, and loop through processing incoming server messages
 *  until tcm is told to quit, is killed, or gives up reconnecting.
 */
int
main(int argc, char *argv[])
{
  int i;
  char c;

  /* chdir returns 0 on sucess, -1 on failure */
  if (chdir(DPATH))
  {
    printf("Unable to chdir to DPATH\n");
    printf("Fatal Error, exiting\n");
    exit(1);
  }
#ifdef HAVE_SETRLIMIT
  setup_corefile();
#endif
  clear_userlist();
  eventInit();			/* event.c stolen from ircd */

  config_entries.conffile=NULL;

  current_time = time(NULL);

  while( (c=getopt(argc, argv, "dvhnf:")) != -1)
    {
      switch (c)
        {
          case 'd':
            config_entries.debug=1;
            break;
          case 'v':
            printf("tcm-hybrid version %s(%s)\n", VERSION, SERIALNUM);
            exit(0);
            /* NOT REACHED */
            break;
          case 'h':
            printf("%s [-h|-v] [-d] [-n] [-f conffile]", argv[0]);
	    printf("-h help\n");
            printf("-v version");
	    printf("-d debug\n");
	    printf("-n nofork\n");
	    printf("-f specify conf file\n");
            exit(0);
            /* NOT REACHED */
            break;
          case 'n':
            config_entries.nofork=1;
            break;
          case 'f':
            config_entries.conffile=optarg;
            break;
        }
    }

  init_hash();
  modules_init();
#if 0
  load_all_modules(YES);
#endif
  init_handlers();
  init_commands();
  init_userlist_handlers();
  init_clones();
  init_vclones();
  init_serv_commands();

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
  init_wingates();
#endif

  init_bothunt();

#ifdef SERVICES
  init_services();
#endif

  if (config_entries.conffile)
    load_config_file(config_entries.conffile);
  else
    load_config_file(CONFIG_FILE);
#ifdef DEBUGMODE
  exempt_summary();
#endif

  init_connections();
  srandom(time(NULL));	/* -zaph */
  signal(SIGUSR1,init_debug);
#if 0
  signal(SIGSEGV,sighandlr);
  signal(SIGBUS,sighandlr);
  signal(SIGTERM,sighandlr);
  signal(SIGINT,sighandlr);
#endif
  signal(SIGHUP, handle_sighup);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTRAP, SIG_IGN);
  /* pick up the name of a pid file from the tcm.cf file */
#ifdef DEBUGMODE
  config_entries.debug=1;
#endif

  if(!config_entries.debug && !config_entries.nofork)
    {
      switch ((i = fork()))
	{
	case -1:
	  fprintf(stderr, "ERROR: Cannot fork process\n");
	  exit(-1);
	  break;
	case 0:
	  /* someone is still using one of these... tsk tsk */
#if 0
	  close(0);
	  close(1);
	  close(2);
#endif
	  (void)setsid(); /* really should disassociate */
	  break;
	default:
	  printf("Launched into background (pid:%d)\n", i);
	  exit(0);
	  break;
	}
    }

  if(config_entries.tcm_pid_file[0] != '\0')
    {
      if ((outfile = fopen(config_entries.tcm_pid_file,"w")) == NULL)
	{
	  fprintf(stderr,"Cannot write %s as given in tcm.cf file\n",
		  config_entries.tcm_pid_file);
	  exit(1);
	}
    }
  else
    {
      if ((outfile = fopen("etc/tcm.pid","w")) == NULL)
	{
	  fprintf(stderr,"Cannot write tcm.pid\n");
	  exit(1);
	}
    }

  (void)fprintf(outfile,"%d\n", (int) getpid());
  (void)fclose(outfile);

  if(config_entries.debug && (outfile != NULL))
    {
       if ((outfile = fopen(DEBUG_LOGFILE,"w")) == NULL)
	 {
	   (void)fprintf(stderr,"Cannot create %s\n",DEBUG_LOGFILE);
	   exit(1);
	 }
    }

  if(connect_to_server(config_entries.server_name,
		       atoi(config_entries.server_port)) == NULL)
    {
      tcm_log(L_ERR, "Could not connect to server at startup");
      exit(1);
    }

  if(config_entries.virtual_host_config[0] != '\0')
    {
      strlcpy(tcm_status.my_hostname, config_entries.virtual_host_config,
	      MAX_HOST);
    }
  else
    {
      gethostname(tcm_status.my_hostname,MAX_HOST-1);
    }

  startup_time = time(NULL);

  /* XXX move into init_tcm_status() later */
  tcm_status.my_class[0] = '\0';
  tcm_status.my_nick[0] = '\0';
  tcm_status.my_server[0] = '\0';
  tcm_status.am_opered = 0;
  tcm_status.ping_time = 0;
  tcm_status.doing_trace = 0;

  /* enter the main IO loop */
  read_packet();

  /* NOT REACHED */
#if 0
  if(config_entries.debug && outfile)
    {
      fclose(outfile);
    }
#endif
  return 0;
}

static void 
init_debug(int sig)
{
  if(config_entries.debug && (outfile != NULL))
    {
      fprintf(outfile, "Debug turned off.\n");
      fclose(outfile);
      outfile = NULL;
      config_entries.debug=0;
    }
  else
    {
      if ((outfile = fopen(DEBUG_LOGFILE, "w")) == NULL)
	{
	  fprintf(stderr, "Cannot create %s\n", DEBUG_LOGFILE);
	  signal(sig, init_debug);
	  return;
	}
      fprintf(outfile, "Debug turned on.\n");
      config_entries.debug=1;
    }
}


#ifdef HAVE_SETRLIMIT
/*
 * setup_corefile
 *
 * inputs       - nothing
 * output       - nothing
 * side effects - setups corefile to system limits.
 * -kre
 *
 * Stolen from Hyb6.2 - Hwy
 */
static void 
setup_corefile(void)
{
  struct rlimit rlim; /* resource limits */

  /* Set corefilesize to maximum */
  if (!getrlimit(RLIMIT_CORE, &rlim))
  {
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_CORE, &rlim);
  }
}
#endif

static void
handle_sighup(int sig)
{
  if(sig != SIGHUP)
    return;

  send_to_all(FLAGS_ALL, "*** Caught SIGHUP ***");
  reload_userlist();
}
  
/*
 * strlcat and strlcpy were ripped from openssh 2.5.1p2
 * They had the following Copyright info:
 *
 *
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */



#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz, dlen;

        while (*d != '\0' && n-- != 0)
                d++;
        dlen = d - dst;
        n = siz - dlen;

        if (n == 0)
                return(dlen + strlen(s));
        while (*s != '\0') {
                if (n != 1) {
                        *d++ = *s;
                        n--;
                }
                s++;
        }
        *d = '\0';
        return(dlen + (s - src));       /* count does not include NUL */
}
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz;
        /* Copy as many bytes as will fit */
        if (n != 0 && --n != 0) {
                do {
                        if ((*d++ = *s++) == 0)
                                break;
                } while (--n != 0);
        }
        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';              /* NUL-terminate dst */
                while (*s++)
                        ;
        }

        return(s - src - 1);    /* count does not include NUL */
}
#endif

/* xmalloc()
 *
 * input	- size to malloc()
 * output	-
 * side effects - memory is malloc()'d, exit() called if failure
 */
void *
xmalloc(size_t size)
{
  void *ret;

  numalloc++;

  ret = malloc(size);

  if (ret == NULL)
  {
    send_to_all(FLAGS_ALL, "Ran out of memory while attempting to allocate");
    exit(-1);
  }

  if (totalmem + size < totalmem)
    {
      totalmem = 0;
    }
  totalmem += size;

  return ret;
}

/*
 * xfree()
 * inputs	- allocated memory to free
 * outputs	- none
 * side effects	- memory passed is no longer allocated
 */

void
xfree(void *p)
{
    numfree++;
    if (p != NULL)
      { 
        free(p);
      }
}
