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

/* $Id: main.c,v 1.32 2002/05/04 20:12:07 einride Exp $ */

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
#include "commands.h"
#include "modules.h"
#include "stdcmds.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#ifdef FORCE_CORE
#include <sys/resource.h>
#endif

extern int errno;          /* The Unix internal error number */
extern FILE *outfile;
extern struct a_entry actions[MAX_ACTIONS+1];
extern int load_all_modules(int log);
extern void init_tokenizer(void);
extern void modules_init(void);
extern void add_common_function(int type, void *function);

struct connection connections[MAXDCCCONNS+1]; /* plus 1 for the server, silly */
struct s_testline testlines;

char ourhostname[MAX_HOST];   /* This is our hostname with domainname */
char serverhost[MAX_HOST];    /* Server tcm will use. */

fd_set writefds;

/* kludge for ensuring no direct loops */
int  incoming_connnum;	      /* current connection number incoming */
/* KLUDGE  *grumble* */
/* allow for ':' ' ' etc. */

#ifdef DEBUGMODE
void write_debug();
#endif

static void init_debug(int sig);

void init_hash_tables(void);

int add_action(char *name);
void set_action_reason(int action, char *reason);
void set_action_method(int action, int method);
void set_action_strip(int action, int hoststrip);
void set_action_time(int action, int klinetime);

#if 0
/* XXX - unused */
int action_log(char *name);
#endif

#if 0
/* XXX - unused */
char *get_action_reason(char *name);
#endif

#ifdef FORCE_CORE
static void setup_corefile(void);
#endif

/*
 * init_hash_tables
 *
 * inputs       - none
 * output       - none
 * side effects -
 */
void init_hash_tables(void)
{
  if (signon)
    memset(signon,0,sizeof(struct common_function));
  if (signoff)
    memset(signoff,0,sizeof(struct common_function));
  if (dcc_signon)
    memset(dcc_signon,0,sizeof(struct common_function));
  if (dcc_signoff)
    memset(dcc_signoff,0,sizeof(struct common_function));
  if (user_signon)
    memset(user_signon,0,sizeof(struct common_function));
  if (user_signoff)
    memset(user_signoff,0,sizeof(struct common_function));
  if (continuous)
    memset(continuous,0,sizeof(struct common_function));
  if (scontinuous)
    memset(scontinuous,0,sizeof(struct common_function));
  if (config)
    memset(config,0,sizeof(struct common_function));
  if (action)
    memset(action,0,sizeof(struct common_function));
  if (reload)
    memset(reload,0,sizeof(struct common_function));
  if (wallops)
    memset(wallops,0,sizeof(struct common_function));
  if (onjoin)
    memset(onjoin,0,sizeof(struct common_function));
  if (onctcp)
    memset(onctcp,0,sizeof(struct common_function));
  if (ontraceuser) memset(ontraceuser,0,sizeof(struct common_function));
  if (ontraceclass)
    memset(ontraceclass,0,sizeof(struct common_function));
  if (server_notice)
    memset(server_notice,0,sizeof(struct common_function));
  if (statsi)
    memset(statsi,0,sizeof(struct common_function));
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
#ifdef DEBUGMODE
	    perror("connect()");
#endif
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

void sendtoalldcc(int type,char *format,...)
{
  va_list va;
  char msgbuf[MAX_BUFF];
  int i;
  int echo;

  va_start(va,format);

  /* we needn't check for \n here because it is done already in prnt() */
  vsnprintf(msgbuf, sizeof(msgbuf), format, va);

  echo = (connections[incoming_connnum].type & TYPE_ECHO);

  for(i = 1; i < maxconns; i++)
    {
      if( !echo && (i == incoming_connnum) )
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
	      
            case SEND_OPERWALL_ONLY:
	    case SEND_LOCOPS_ONLY:
#ifdef ENABLE_W_FLAG
              if (!(connections[i].type & TYPE_OPERWALL))
                break;
#endif
	    case SEND_WALLOPS_ONLY:
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
    
  sendtoalldcc(SEND_ALL_USERS, "%s %s (%s@%s) has disconnected",
               connections[connnum].type & TYPE_OPER ? "Oper" : "User", 
               connections[connnum].nick, connections[connnum].user,
               connections[connnum].host);

  connections[connnum].user[0] = '\0';
  connections[connnum].host[0] = '\0';
  connections[connnum].nick[0] = '\0';
  connections[connnum].registered_nick[0] = '\0';
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

int add_action(char *name)
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
    actions[i].hoststrip = HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL;
  }
  return i;
}

void set_action_time(int action, int klinetime) {
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]))
    actions[action].klinetime = klinetime;
}

void set_action_strip(int action, int hoststrip)
{
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]))
    actions[action].hoststrip = hoststrip;
}

void set_action_method(int action, int method)
{
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]))
    actions[action].method = method;    
}

void set_action_reason(int action, char *reason)
{
  if ((action>=0) && (action < MAX_ACTIONS) && (actions[action].name[0]) && reason && reason[0])
    snprintf(actions[action].reason, sizeof(actions[action].reason), "%s", reason);
}

int find_action(char *name)
{
  int i;
  for (i=0 ; i<MAX_ACTIONS ; ++i)
    if (!strcasecmp(name, actions[i].name)) 
      return i;
  return -1;
}

#if 0
/* XXX - unused */
int action_log(char *name)
{
  int i;
  if ((i = get_action(name)) == -1) return 0;
  return (actions[i].report ? YES : NO);
}
#endif

#if 0
/* XXX - unused */
char *get_action_reason(char *name)
{
  int i;
  if ((i = get_action(name)) == -1) return NULL;
  return actions[i].reason;
}
#endif

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

  /* chdir returns 0 on sucess, -1 on failure */
  if (chdir(DPATH))
  {
    printf("Unable to chdir to DPATH\nFatal Error, exiting\n");
    exit(1);
  }
#ifdef FORCE_CORE
  setup_corefile();
#endif
  init_hash_tables();		/* clear those suckers out */
  init_tokenizer();		/* in token.c */
  init_userlist();

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
  add_common_function(F_DCC_SIGNOFF, closeconn);
  load_all_modules(YES);

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
  signal(SIGSEGV,sighandlr);
  signal(SIGBUS,sighandlr);
  signal(SIGTERM,sighandlr);
  signal(SIGINT,sighandlr);
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
      fprintf(stderr,"Memory allocation error in main()\n");
#ifdef DEBUGMODE
      printf("Memory allocation error in main()\n");
#endif
      exit(1);
    }
  memset(connections[0].buffer, 0, BUFFERSIZE);   /* I'm not really sure why this is needed, but it fixed rtmon */

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
  if (sig == SIGINT)
    {
      toserv("QUIT :Ctrl+C; Exiting...\n");
      gracefuldie(0, __FILE__, __LINE__);
    }
  else
    gracefuldie(sig, __FILE__, __LINE__);
  signal(sig, sighandlr);
}

#ifdef IRCD_HYBRID

#else

void m_unregistered(int connnum, int argc, char *argv[])
{
  prnt(connnum, "You have not registered\n");
}

void m_not_oper(int connnum, int argc, char *argv[])
{
  prnt(connnum, "Only authorized opers may use this command\n");
}

void m_not_admin(int connnum, int argc, char *argv[])
{
  prnt(connnum, "Only authorized admins may use this command\n");
}
#endif

#ifdef FORCE_CORE
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
static void setup_corefile(void)
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
