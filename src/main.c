/* Beginning of major overhaul 9/3/01 */

/* $Id: main.c,v 1.60 2002/05/25 02:40:40 db Exp $ */

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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "event.h"
#include "serverif.h"
#include "userlist.h"
#include "bothunt.h"
#include "commands.h"
#include "modules.h"
#include "stdcmds.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"
#include "parse.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

extern FILE *outfile;
extern struct a_entry actions[MAX_ACTIONS+1];
extern int load_all_modules(int log);
extern void init_tokenizer(void);
extern void modules_init(void);

#ifdef SERVICES
extern int act_drone, act_sclone;
#endif

struct connection connections[MAXDCCCONNS+1]; /* plus 1 for the server, silly */
struct s_testline testlines;

time_t current_time;

char ourhostname[MAX_HOST];   /* This is our hostname with domainname */
char serverhost[MAX_HOST];    /* Server tcm will use. */

/* kludge for ensuring no direct loops */
int  incoming_connnum;	      /* current connection number incoming */
/* KLUDGE  *grumble* */
/* allow for ':' ' ' etc. */

#ifdef DEBUGMODE
void write_debug();
#endif

static void init_debug(int sig);

int add_action(char *name);
void set_action_reason(int action, char *reason);
void set_action_method(int action, int method);
void set_action_strip(int action, int hoststrip);
void set_action_time(int action, int klinetime);

#ifdef HAVE_SETRLIMIT
static void setup_corefile(void);
#endif

/*
 * bindsocket()
 *   Sets up a socket and connects to the given host and port
 */
int
bindsocket(char *hostport)
{
  int plug;
  struct sockaddr_in socketname;
  struct sockaddr_in localaddr;
  struct hostent *remote_host;
  /* virtual host support - dianora */
  struct hostent *local_host;
  int portnum = 6667;
  char server[MAX_HOST];
  char *hold;
  int optval;
  unsigned long remoteaddr;

  /* Parse serverhost to look for port number */
  strcpy (server,hostport);

  if ((hold = strchr(server,':')))
    {
      *(hold++) = '\0';
      portnum = atoi(hold);
    }

  /* open an inet socket */
  if ((plug = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      send_to_all(SEND_ALL,
		   "Can't assign fd for socket\n");
      exit(0);
    }

  optval = 1;

  (void)setsockopt(plug,SOL_SOCKET,SO_REUSEADDR,(char *)&optval,
		   sizeof(optval));
  (void) memset(&socketname, 0, sizeof(socketname));

  /* virtual host support  */
  if(config_entries.virtual_host_config[0])
    {
      if ((local_host = gethostbyname (config_entries.virtual_host_config)) )
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "virtual host [%s]\n",
		      config_entries.virtual_host_config);
	      fprintf(outfile, "found official name [%s]\n",
		      local_host->h_name);
	    }

	  (void) memset(&localaddr, 0, sizeof(struct sockaddr_in));
	  (void) memcpy ((void *) &localaddr.sin_addr,
			 (void *) local_host->h_addr,
			 local_host->h_length);
	  localaddr.sin_family = AF_INET;
	  localaddr.sin_port = 0;

	  if(bind(plug,(struct sockaddr *)&localaddr,
	       sizeof(socketname)) < 0)
	    {
	      if(config_entries.debug && outfile)
		{
		  fprintf(outfile, "unable to bind virtual host");
		}
	    }
	  else
	    {
	      if(config_entries.debug && outfile)
		{
		  fprintf(outfile, "bound to virtual host\n");
		}
	    }
	}
    }
      
  socketname.sin_family = AF_INET;
  socketname.sin_port = htons (portnum);

  /* kludge for DCC CHAT precalculated sin_addrs */
  if (*server == '#')
    {
       (void)sscanf(server+1,"%lu",&remoteaddr);
       /* Argh.  Didn't they teach byte order in school??? --cah */
       socketname.sin_addr.s_addr=htonl(remoteaddr);
    }
  /* lookup host */
  else
    {
      if ( !(remote_host = gethostbyname (server)) )
	{
	  printf ("error: unknown host: %s\n", server);
	  return (INVALID);
	}
      (void) memcpy ((void *) &socketname.sin_addr,
		    (void *) remote_host->h_addr,
		    remote_host->h_length);
    }

  /* connect socket */
  while(connect (plug, (struct sockaddr *) &socketname, sizeof socketname) < 0)
    if (errno != EINTR)
      {
	close(plug);
	if( config_entries.debug && outfile)
	  {
	    fprintf(outfile, "Error: connect %i\n", errno);
#ifdef DEBUGMODE
	    perror("connect()");
#endif
	  }
	return (INVALID);
      }
  return (plug);
}


/*
 * closeconn()
 *
 * inputs	- connection number
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */

void
closeconn(int connnum, int argc, char *argv[])
{
  int i;

  if (connections[connnum].socket != INVALID)
    close(connections[connnum].socket);

  connections[connnum].socket = INVALID;

  if ((connnum + 1) == maxconns)
    {
      for (i=maxconns;i>0;--i)
	if (connections[i].socket != INVALID)
	  break;
      maxconns = i+1;
    }
    
  send_to_all(SEND_ALL,
	       "Oper %s (%s@%s) has disconnected",
               connections[connnum].nick, connections[connnum].user,
               connections[connnum].host);

  connections[connnum].user[0] = '\0';
  connections[connnum].host[0] = '\0';
  connections[connnum].nick[0] = '\0';
  connections[connnum].registered_nick[0] = '\0';
}

int
add_action(char *name)
{
  int i;

  if (name == NULL)
    return -1;

  for (i=0;i<MAX_ACTIONS;++i)
    {
      if ((!actions[i].name[0]) || (!strcasecmp(actions[i].name, name)))
	break;
    }
  if (i == MAX_ACTIONS)
    {
      fprintf(outfile, "add_action() failed to find free space\n");
      return -1;
    }
  if (!actions[i].name[0]) {
    snprintf(actions[i].name, sizeof(actions[i].name), "%s", name);
    actions[i].method = METHOD_IRC_WARN | METHOD_DCC_WARN;
    actions[i].klinetime = 60;
    actions[i].hoststrip = HS_DEFAULT;
  }
  return i;
}

void
set_action_time(int action, int klinetime)
{
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]))
    actions[action].klinetime = klinetime;
}

void
set_action_strip(int action, int hoststrip)
{
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]))
    actions[action].hoststrip = hoststrip;
}

void
set_action_method(int action, int method)
{
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]))
    actions[action].method = method;    
}

void
set_action_reason(int action, char *reason)
{
  if ((action>=0) && (action < MAX_ACTIONS) &&
      (actions[action].name[0]) && reason && reason[0])
    snprintf(actions[action].reason,
	     sizeof(actions[action].reason), "%s", reason);
}

int
find_action(char *name)
{
  int i;
  for (i=0 ; i<MAX_ACTIONS ; ++i)
    if (!strcasecmp(name, actions[i].name)) 
      return i;
  return -1;
}

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
    printf("Unable to chdir to DPATH\nFatal Error, exiting\n");
    exit(1);
  }
#ifdef HAVE_SETRLIMIT
  setup_corefile();
#endif
  init_tokenizer();		/* in token.c */
  init_userlist();
  eventInit();			/* event.c stolen from ircd */

  config_entries.conffile=NULL;

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
            printf("%s [-h|-v] [-d] [-n] [-f conffile]\n-h help\n", argv[0]);
            printf("-v version\n-d debug\n-n nofork\n-f specify conf file\n");
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

  memset(&actions, 0, sizeof(actions));

  modules_init();
#if 0
  load_all_modules(YES);
#endif

  init_commands();
#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
  init_wingates();
#endif

#ifdef GLINES
  mod_add_cmd(&gline_msgtab);
#endif

  init_bothunt();

#ifdef SERVICES
  act_sclone = add_action("sclone");
  set_action_strip(act_sclone, HS_SCLONE);
  set_action_reason(act_sclone, REASON_SCLONE);

#ifdef SERVICES_DRONES
  act_drone = add_action("drone");
  set_action_strip(act_drone, HS_DRONE);
  set_action_reason(act_drone, REASON_DRONE);
#endif
#endif

  if (config_entries.conffile)
    load_config_file(config_entries.conffile);
  else
    load_config_file(CONFIG_FILE);
  load_userlist();
#ifdef DEBUGMODE
  exemption_summary();
#endif

  snprintf(serverhost,sizeof(serverhost), "%s:%d", config_entries.server_name, 
           atoi(config_entries.server_port));

  for (i=0;i<MAXDCCCONNS+1;++i)
    {
      connections[i].socket = INVALID;
      connections[i].user[0] = '\0';
      connections[i].host[0] = '\0';
      connections[i].nick[0] = '\0';
      connections[i].registered_nick[0] = '\0';
    }

  srandom(time(NULL));	/* -zaph */
  signal(SIGUSR1,init_debug);
#if 0
  signal(SIGSEGV,sighandlr);
  signal(SIGBUS,sighandlr);
  signal(SIGTERM,sighandlr);
  signal(SIGINT,sighandlr);
#endif
  signal(SIGHUP,reload_user_list);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTRAP, SIG_IGN);
  /* pick up the name of a pid file from the tcm.cf file */
#ifdef DEBUGMODE
  config_entries.debug=1;
#endif

  if(!config_entries.debug && !config_entries.nofork)
    {
      i = fork();
      if (i == -1)
	{
	  fprintf(stderr, "ERROR: Cannot fork process\n");
	  exit(-1);
	}
      else if (i)
	{
	  printf("Launched into background (pid:%d)\n", i);
	  exit(0);
	}
      else if ( i == 0 )
	{
	  /* someone is still using one of these... tsk tsk */
#if 0
	  close(0);
	  close(1);
	  close(2);
#endif
	  (void)setsid(); /* really should disassociate */
	}
    }

  if(config_entries.tcm_pid_file[0])
    {
      if( !(outfile = fopen(config_entries.tcm_pid_file,"w")) )
	{
	  fprintf(stderr,"Cannot write %s as given in tcm.cf file\n",
		  config_entries.tcm_pid_file);
	  exit(1);
	}
    }
  else
    {
      if( !(outfile = fopen("etc/tcm.pid","w")) )
	{
	  fprintf(stderr,"Cannot write tcm.pid\n");
	  exit(1);
	}
    }

  (void)fprintf(outfile,"%d\n", (int) getpid());
  (void)fclose(outfile);

  if(config_entries.debug && outfile)
    {
       if( !(outfile = fopen(DEBUG_LOGFILE,"w")) )
	 {
	   (void)fprintf(stderr,"Cannot create %s\n",DEBUG_LOGFILE);
	   exit(1);
	 }
    }
  connections[0].socket = bindsocket(serverhost);
  if (connections[0].socket == INVALID)
    exit(1);
  connections[0].nbuf = 0;
  connections[0].type = 0;
  maxconns = 1;

  if(config_entries.virtual_host_config[0])
    {
      strncpy(ourhostname,config_entries.virtual_host_config,MAX_HOST-1);
    }
  else
    {
      gethostname(ourhostname,MAX_HOST-1);
    }
  *mynick = '\0';
  pingtime = 0;
  memset((void *)&myclass, sizeof(myclass), 0);

  amianoper = NO;
  startup_time = time(NULL);
  _signon(0, 0, NULL);

  /* enter the main IO loop */
  while(!quit)
    read_packet();

  linkclosed(0, 0, NULL);

  if(config_entries.debug && outfile)
    {
      fclose(outfile);
    }

  return 0;
}

static void 
init_debug(int sig)
{
  if(config_entries.debug && outfile)
    {
      fprintf(outfile, "Debug turned off.\n");
      fclose(outfile);
      outfile = NULL;
      config_entries.debug=0;
    }
  else
    {
      if ( !(outfile = fopen(DEBUG_LOGFILE, "w")) )
	{
	  fprintf(stderr, "Cannot creat %s\n", DEBUG_LOGFILE);
	  signal(sig, init_debug);
	  return;
	}
      fprintf(outfile, "Debug turned on.\n");
      config_entries.debug=1;
    }
}

#ifdef IRCD_HYBRID

#else

void
m_unregistered(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "You have not registered\n");
}

void
m_not_oper(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
       "Only authorized opers may use this command\n");
}

void
m_not_admin(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
       "Only authorized admins may use this command\n");
}
#endif

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

/*
 * expand_args
 *
 * inputs	- pointer to output
 *		- max length of output
 *		- argc
 *		- *argv[]
 * output	- none
 * side effects	- This function takes a set of argv[] and expands
 *		  it back out. basically the reverse of parse_args().
 */
void
expand_args(char *output, int maxlen, int argc, char *argv[])
{
  int curlen=0;
  int len;
  int i;

  for (i = 0; i < argc; i++)
  {
    len = strlen(argv[i]) + 1;
    if ((len + curlen) >= maxlen) 
      {
	*output = '\0';
	return;
      }
    sprintf(output,"%s ", argv[i]);
    output += len;
    curlen += len;
  }
  /* blow away last ' ' */
  *--output = '\0';
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

