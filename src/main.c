/* Beginning of major overhaul 9/3/01 */

/************************************************************
* Mrsbot (used in tcm) by Hendrix <jimi@texas.net>          *
*                                                           *
*   Main program is here.                                   *
*   Code to log into server and parse server commands       *
*   and call routine based on the type of message (public,  *
*   private, mode change, etc.)                             *
*   Based heavily on Adam Roach's bot skeleton.             *
************************************************************/

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
#include <unistd.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#ifdef AIX
# include <sys/select.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include "config.h"
#include "tcm.h"
#include "serverif.h"
#include "userlist.h"
#include "bothunt.h"
#include "modules.h"
/*#include "token.h"
#include "logging.h"
#include "stdcmds.h"
#include "commands.h"
#include "wild.h"*/
#include "serno.h"
#include "patchlevel.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: main.c,v 1.5 2001/10/11 16:04:57 bill Exp $";

extern int errno;          /* The Unix internal error number */
extern FILE *outfile;
extern struct a_entry actions[100];
extern int load_all_modules(int log);

unsigned long local_ip(void);
struct connection connections[MAXDCCCONNS+1]; /* plus 1 for the server, silly */

char ourhostname[MAX_HOST];   /* This is our hostname with domainname */
char serverhost[MAX_HOST];    /* Server tcm will use. */
char allow_nick[MAX_ALLOW_SIZE][MAX_NICK+4];

fd_set writefds;

/* kludge for ensuring no direct loops */
int  incoming_connnum;	      /* current connection number incoming */
/* KLUDGE  *grumble* */
/* allow for ':' ' ' etc. */

#ifdef DEBUGMODE
void add_placed (char *file, int line);
void write_debug();
#endif

static void init_debug(int sig);

/*
 * init_hash_tables
 *
 * inputs       - none
 * output       - none
 * side effects -
 */
void init_hash_tables(void)
{
  if (signon) memset(signon,0,sizeof(struct common_function));
  if (signoff) memset(signoff,0,sizeof(struct common_function));
  if (dcc_signon) memset(dcc_signon,0,sizeof(struct common_function));
  if (dcc_signoff) memset(dcc_signoff,0,sizeof(struct common_function));
  if (user_signon) memset(user_signon,0,sizeof(struct common_function));
  if (user_signoff) memset(user_signoff,0,sizeof(struct common_function));
  if (continuous) memset(continuous,0,sizeof(struct common_function));
  if (scontinuous) memset(scontinuous,0,sizeof(struct common_function));
  if (config) memset(config,0,sizeof(struct common_function));
  if (prefsave) memset(prefsave,0,sizeof(struct common_function));
  if (action) memset(action,0,sizeof(struct common_function));
  if (reload) memset(reload,0,sizeof(struct common_function));
  if (wallops) memset(wallops,0,sizeof(struct common_function));
  if (onjoin) memset(onjoin,0,sizeof(struct common_function));
  if (onctcp) memset(onctcp,0,sizeof(struct common_function));
  if (ontraceuser) memset(ontraceuser,0,sizeof(struct common_function));
  if (ontraceclass) memset(ontraceclass,0,sizeof(struct common_function));
  if (server_notice) memset(server_notice,0,sizeof(struct common_function));
  if (statsi) memset(statsi,0,sizeof(struct common_function));
}

/*
 * init_allow_nick(void)
 *
 * inputs       - NONE
 * output       - NONE
 * side effects - The allow nick table is cleared out.
 */

void init_allow_nick()
{
  int i;
#ifdef DEBUGMODE
  placed;
#endif

  for(i=0;i<MAX_ALLOW_SIZE;i++)
    {
      allow_nick[i][0] = '-';
      allow_nick[i][1] = '\0';
    }
}

/*
** bindsocket()
**   Sets up a socket and connects to the given host and port
*/
int bindsocket(char *hostport)
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
#ifdef DEBUGMODE
  placed;
#endif

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
      sendtoalldcc(SEND_ALL_USERS, "Can't assign fd for socket\n");
      exit(0);
      return (INVALID);
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
	  }
	return (INVALID);
      }
  
  return (plug);
}

/*
 * sendtoalldcc
 *
 * inputs	- message to send
 *		- flag if message is to be sent only to all users or opers only
 * output	- NONE
 * side effects	- message is sent on /dcc link to all connected
 *		  users or to only opers on /dcc links
 *
 */

void sendtoalldcc(int type,...)
{
  va_list va;
  char msgbuf[MAX_BUFF];
  char *format;
  int i;
  int echo;
  int local_tcm = NO;	/* local tcm ? */
#ifdef DEBUGMODE
  placed;
#endif

  va_start(va,type);

  format = va_arg(va, char *);
  /* we needn't check for \n here because it is done already in prnt() */
  vsnprintf(msgbuf, sizeof(msgbuf), format, va);

  echo = (connections[incoming_connnum].type & TYPE_ECHO);

  for(i = 1; i < maxconns; i++)
    {
      if( !echo && (i == incoming_connnum) )
	continue;
      else if( ((connections[i].type & TYPE_TCM)
		&& (i == incoming_connnum )) )
	continue;

      if (connections[i].socket != INVALID)
	{
	  switch(type)
	    {
	    case SEND_KLINE_NOTICES_ONLY:
	      if (connections[i].type & TYPE_KLINE)
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_MOTD_ONLY:
	      if (connections[i].type & TYPE_MOTD)
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_LINK_ONLY:
	      if (connections[i].type & TYPE_LINK)
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_WARN_ONLY:
	      if (connections[i].type & TYPE_WARN)
		prnt(connections[i].socket, msgbuf);
	      break;
	      
	    case SEND_WALLOPS_ONLY:
	    case SEND_LOCOPS_ONLY:
	      if (connections[i].type & TYPE_LOCOPS)
		prnt(connections[i].socket, msgbuf);
	      break;
	      
	    case SEND_OPERS_STATS_ONLY:
	      if(connections[i].type & TYPE_STAT)
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_OPERS_ONLY:
	      if(connections[i].type & (TYPE_OPER | TYPE_WARN))
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_OPERS_PRIVMSG_ONLY:
	      if((connections[i].type & TYPE_OPER) &&
		 (connections[i].set_modes & SET_PRIVMSG))
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_OPERS_NOTICES_ONLY:
	      if((connections[i].type & TYPE_OPER) &&
		 (connections[i].set_modes & SET_NOTICES))
		prnt(connections[i].socket, msgbuf);
	      break;

	    case SEND_ALL_USERS:
	      if(connections[i].type & TYPE_PARTYLINE)
	        prnt(connections[i].socket, msgbuf);
	      break;

	    default:
	      break;
	    }
	}
    }
    va_end(va);
}

/*
 * closeconn()
 *
 * inputs	- connection number
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */

void closeconn(int connnum, int argc, char *argv[])
{
  int i;
#ifdef DEBUGMODE
  placed;
#endif

  if (connections[connnum].socket != INVALID)
    close(connections[connnum].socket);

  if(connections[connnum].buffer)
    free (connections[connnum].buffer);

  connections[connnum].buffer = (char *)NULL;
  connections[connnum].socket = INVALID;

  if ((connnum + 1) == maxconns)
    {
      for (i=maxconns;i>0;--i)
	if (connections[i].socket != INVALID)
	  break;
      maxconns = i+1;
    }
    
  connections[connnum].user[0] = '\0';
  connections[connnum].host[0] = '\0';
  connections[connnum].nick[0] = '\0';
  connections[connnum].registered_nick[0] = '\0';
}

/* 
 * local_ip()
 * 
 * inputs		- NONE
 * output		- ip of local host
 * side effects	- NONE
 */

unsigned long local_ip(void)
{
  struct hostent *local_host;
  unsigned long l_ip;

  if(config_entries.virtual_host_config[0])
    {
      if ((local_host = gethostbyname (config_entries.virtual_host_config)))
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "virtual host [%s]\n",
		      config_entries.virtual_host_config);
	      fprintf(outfile, "found official name [%s]\n",
		      local_host->h_name);
	    }

          memcpy((void *)&l_ip,(void *)local_host->h_addr,
		 sizeof(local_host->h_addr));

	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "DEBUG: %lu %lX\n", l_ip, l_ip);
	    }
	  return(htonl(l_ip));
	}
    }
  else
    {
      if ((local_host = gethostbyname (ourhostname)) )
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "found official name [%s]\n",
		      local_host->h_name);
	    }

	  (void) memcpy((void *) &l_ip,(void *) local_host->h_addr,
			sizeof(local_host->h_addr));

	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "DEBUG: %lu %lX\n", l_ip, l_ip);
	    }
	  return(htonl(l_ip));
	}
    }
  /* NOT REACHED */
  return 0L;
}

/*
** gracefuldie()
**   Called when we encounter a segmentation fault.
**   Parameters: None
**   Returns: void
**   PDL:
**     While debugging, I got so many seg faults that it pissed me off enough
**     to write this.  When dying from a seg fault, open files are not closed.
**     This means I lose the last 8K or so that was appended to the debug
**     logfile, including the thing that caused the seg fault.  This will
**     close the file before dying... Not too much more graceful, I agree.
*/
void gracefuldie(int sig, char *file, int line)
{
  if(config_entries.debug && outfile)
    {
      fprintf(outfile, "gracefuldie() %s/%d\n", file, line);
      fclose(outfile);
      fprintf(stderr, "gracefuldie() %s/%d", file, line);
      if (sig) fprintf(stderr, " sig: %d\n", sig);
      else
	fprintf(stderr, "\n");
    }

  if (sig != SIGTERM) {
    toserv("QUIT :Woo hoo!  TCM crash!\n");
    abort();
  } else toserv("QUIT :Leaving\n");
  exit(1);
}

void add_action(char *name, char *method, char *reason, int report)
{
  int i;
  if (!name) return;

  for (i=0;i<MAX_ACTIONS;++i)
    {
      if (!actions[i].method[0]) break;
    }
  if (actions[i].method[0])
    {
      fprintf(outfile, "add_action() failed to find free space\n");
      return;
    }
  if (!actions[i].name[0])
    snprintf(actions[i].name, sizeof(actions[i].name), "%s", name);
  if (!actions[i].method[0])
    snprintf(actions[i].method, sizeof(actions[i].method), "%s", method);
  if (reason && !actions[i].method[0])
    snprintf(actions[i].reason, sizeof(actions[i].reason), "%s", reason);
  else if (!actions[i].method[0])
    snprintf(actions[i].reason, sizeof(actions[i].reason), "kline");
}

void set_action_type(char *name, int type)
{
  int index;
  if ((index = get_action(name)) == -1) return;
  else actions[index].type = type;
}

void set_action_method(char *name, char *method)
{
  int index;
  if ((index = get_action(name)) == -1) return;
  snprintf(actions[index].method, sizeof(actions[index].method), "%s", method);
}

void set_action_reason(char *name, char *reason)
{
  int index;
  if ((index = get_action(name)) == -1) return;
  snprintf(actions[index].reason, sizeof(actions[index].reason), "%s", reason);
}

int get_action(char *name)
{
  int index;
  for (index=0;index<MAX_ACTIONS;++index)
    if (!strcasecmp(name, actions[index].name)) break;
  if (strcasecmp(name, actions[index].name)) return 0;
  return index;
}

int get_action_type(char *name)
{
  int index;
  if ((index = get_action(name)) == -1) return 0;
  else return actions[index].type;
}

int action_log(char *name)
{
  int index;
  if ((index = get_action(name)) == -1) return 0;
  return (actions[index].report ? YES : NO);
}

char *get_action_method(char *name)
{
  int index;
  if ((index = get_action(name)) == -1) return NULL;
  return actions[index].method;
}

char *get_action_reason(char *name)
{
  int index;
  if ((index = get_action(name)) == -1) return NULL;
  return actions[index].reason;
}

/*
** main()
**   Duh, hey chief... What does a main do?
**   Parameters:
**     argc - Count of command line arguments
**     argv - List of command line arguments
**   Returns: When the program dies.
**   PDL:
**  
**  tcm only accepts one argument now, the name of a tcm.cf file, then
**  set up assorted things: random numbers, handlers for seg faults and timers,
**  Attach tcm to the server, sign her on to IRC, join her up
**  to the channel, and loop through processing incoming server messages
**  until tcm is told to quit, is killed, or gives up reconnecting.
*/
int main(int argc, char *argv[])
{
  int i;
  char c;
  extern char *optarg;
  extern int optind;
  struct common_function *temp;

  init_hash_tables();		/* clear those suckers out */
  init_tokenizer();		/* in token.c */
  init_userlist();

#ifdef DEBUGMODE		/* initialize debug list */
  for(i=0;i<16;++i) placed;
  i=0;
#endif

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

  for (i=0;i<MAX_ACTIONS;++i)
    {
      actions[i].method[0] = '\0';
      actions[i].reason[0] = '\0';
      actions[i].type = 0;
    }

  modules_init();
  add_common_function(F_DCC_SIGNOFF, closeconn);
/*  dcc_signoff->function = closeconn;
  dcc_signoff->next = (struct common_function *)NULL;
  dcc_signoff->type = F_DCC_SIGNOFF;*/
  load_all_modules(YES);

  if (config_entries.conffile)
    load_config_file(config_entries.conffile);
  else
    load_config_file(CONFIG_FILE);
  load_userlist();
  load_prefs();

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
  signal(SIGSEGV,sighandlr);
  signal(SIGBUS,sighandlr);
  signal(SIGTERM,sighandlr);
  signal(SIGINT,sighandlr);
  signal(SIGHUP,reload_user_list);

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

  (void)fprintf(outfile,"%d\n", getpid());
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
  connections[0].buffer = (char *)malloc(BUFFERSIZE);

  if( !connections[0].buffer )
    {
      fprintf(stderr,"memory allocation error in main()\n");
      exit(1);
    }

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

  amianoper = NO;
  startup_time = time(NULL);
  init_allow_nick();
  for (temp=signon;temp;temp=temp->next)
    temp->function(0, 0, NULL);

  while(!quit)
    {
      for (temp=upper_continuous;temp;temp=temp->next)
        temp->function(0, 0, NULL);
      quit=YES;
    }

  for (temp=signoff;temp;temp=temp->next)
    temp->function(0, 0, NULL);

  if(config_entries.debug && outfile)
    {
      fclose(outfile);
    }

  return 0;
}

/* 
 * init_remote_tcm_listen
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- just listen on tcm_port port. nothing fancy.
 *
 */

void init_remote_tcm_listen(void)
{
  struct sockaddr_in socketname;

/* 
 * If its an invalid port, i.e. less than 1024 or -1 do not listen
 * This will disable remote tcm linking entirely
 */

  if(config_entries.tcm_port <= 1024)
    {
      remote_tcm_socket = -1;
      return;
    }

  memset(&socketname,0,sizeof(struct sockaddr));
  socketname.sin_family = AF_INET;
  socketname.sin_addr.s_addr = INADDR_ANY;
  socketname.sin_port = htons(config_entries.tcm_port);

  if( (remote_tcm_socket = socket(PF_INET,SOCK_STREAM,6)) < 0)
    {
      log_problem("init_remote_tcm_list","Cannot create socket for remote tcm");
      return;
    }

  if(bind(remote_tcm_socket,(struct sockaddr *)&socketname,
	  sizeof(socketname)) < 0)
    {
      fprintf(stderr,"Can't bind TCM_PORT %d\n",TCM_PORT);
      log_problem("init_remote_tcm_list","Can't bind tcm port");
      return;
    }

  if ( listen(remote_tcm_socket,4) < 0 )
    {
      fprintf(stderr,"Can't listen on TCM_PORT\n");
      log_problem("init_remote_tcm_list","Can't listen on tcm port");
      return;
    }
}

static void init_debug(int sig)
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

void sighandlr(int sig)
{
#ifdef DEBUGMODE
  write_debug();
#endif
  if (sig == SIGINT)
    {
      toserv("QUIT :Ctrl+C; Exiting...\n");
      gracefuldie(0, __FILE__, __LINE__);
    }
  else
    gracefuldie(sig, __FILE__, __LINE__);
  signal(sig, sighandlr);
}

#ifdef DEBUGMODE
void add_placed (char *file, int line)
{
  int a;
  for(a=0;a<16;++a)
    {
      if (!placef[a][0])
	{
	  snprintf(placef[a], sizeof(placef[a]), "%s", file);
	  placel[a] = line;
	  return;
	}
    }
  for(a=1;a<=16;++a)
    {
      snprintf(placef[a-1], sizeof(placef[a-1]), "%s", placef[a]);
      placel[a-1]=placel[a];
    }
  snprintf(placef[15], sizeof(placef[15]), "%s", file);
  placel[15] = line;
}

void write_debug()
{
  int a, x;
  time_t now;
  char buff[MAX_BUFF];
  x = creat("DEBUG", 0640);
  now = time(NULL);
  if (x < 0)
    {
      fprintf(stderr, "Error writing DEBUG: %s\n", strerror(errno));
      return;
    }
  snprintf(buff, sizeof(buff) - 1,
	   "DEBUG Wrote %s\nFunction History:\n", ctime(&now));
  write(x, buff, strlen(buff));
  for(a=0;a<15;++a)
    {
      snprintf(buff, sizeof(buff) - 1, " %s/%d\n", placef[a], placel[a]);
      write(x, buff, strlen(buff));
    }
  snprintf(buff, sizeof(buff) - 1,
	   "Last function:\t%s/%d\n", placef[15], placel[15]);
  write(x, buff, strlen(buff));
  close(x);
}
#endif

#ifdef IRCD_HYBRID

#else
void m_unregistered(int connnum, int argc, char *argv[]) {
  prnt(connnum, "You have not registered\n");
}

void m_not_oper(int connnum, int argc, char *argv[]) {
  prnt(connnum, "Only authorized opers may use this command\n");
}

void m_not_admin(int connnum, int argc, char *argv[]) {
  prnt(connnum, "Only authorized admins may use this command\n");
}
#endif
