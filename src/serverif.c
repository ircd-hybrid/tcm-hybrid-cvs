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
#include "token.h"
#include "bothunt.h"
#include "userlist.h"
#include "abuse.h"
#include "serverif.h"
#include "logging.h"
#include "stdcmds.h"
#include "commands.h"
#include "wild.h"
#include "serno.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: serverif.c,v 1.11 2001/02/02 04:04:28 wcampbel Exp $";

extern int errno;          /* The Unix internal error number */

static void send_umodes(char *mynick);
static void onjoin(char *nick, char *mychannel);
static void onkick(char *nick, char *channel);
static void onnick(char *old_nick, char *new_nick);
static void onnicktaken(void);
static void cannotjoin(char *channel);
static void init_debug(int);
static void wallops(char *source, char *params, char *body);
static void linkclosed(char *);
static void serverproc(void);
static void proc(char *source,char *function, char *body);
static void initiate_dcc_chat(char *nick, char *user, char *host);
static unsigned long local_ip(void);
static void privmsgproc(char *nick,char *userhost,char *body);
static void connect_remote_tcm(int);	
static void connect_remote_client(char *,char *,char *,int);
#ifdef SERVICES
static void check_services();
static void on_services_notice(char *);
#endif
static void rdpt(void);
static void signon(void);
static void reload_user_list(int sig);

char ourhostname[MAX_HOST];   /* This is our hostname with domainname */
char serverhost[MAX_HOST];    /* Server tcm will use. */

/* kludge for ensuring no direct loops */
int  incoming_connnum;	      /* current connection number incoming */
/* KLUDGE  *grumble* */
/* allow for ':' ' ' etc. */

static char mychannel[MAX_CHANNEL];	/* tcm's current channel */
static char mynick[MAX_NICK];		/* tcm's current nickname */
static int  amianoper;			/* am I opered? */

/* remote dcc stuff should be in a struct */
int initiated_dcc_socket=(-1);	/* listening for dcc connect */
time_t initiated_dcc_socket_time;

char initiated_dcc_nick[MAX_NICK];
char initiated_dcc_user[MAX_USER];
char initiated_dcc_host[MAX_HOST];

#ifdef DEBUGMODE
void add_placed (char *file, int line);
void write_debug();
#endif

int quit = NO;             /* When it is YES, quit */

int remote_tcm_socket=-1;  /* listening socket */
fd_set readfds;            /* file descriptor set for use with select */

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
fd_set writefds;	   /* file descriptor set for user with select */
#endif

#ifdef DETECT_WINGATE
static void report_open_wingate(int i);
struct wingates wingate[MAXWINGATES];
#endif

#ifdef DETECT_SOCKS
static void report_open_socks(int i);
struct wingates socks[MAXSOCKS];
#endif

struct connection connections[MAXDCCCONNS+1];

int  maxconns = 0;

#ifdef SERVICES
/* For talking to services */
struct services_entry services;
#endif

extern int kline_rec_index;

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
#if 0
      printf ("error: can't assign fd for socket\n");
#endif
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

#ifdef DETECT_WINGATE
/*
** wingate_bindsocket()
**   Sets up a socket and connects to the given host
*/
int wingate_bindsocket(char *nick,char *user,char *host,char *ip)
{
  int plug;
  int result;
  struct hostent *remote_host;
  int flags;
  int optval;
  int i;
  int found_slot = INVALID;
  placed;

  for(i=0;i<MAXWINGATES;i++)
    {
      if(wingate[i].socket == INVALID)
	{
	  found_slot = i;
	  break;
	}
    }

  if(found_slot == INVALID)
    return INVALID;

  /* open an inet socket */
  if ((plug = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      fprintf (stderr, "error: can't assign fd for socket\n");
      return (INVALID);
    }

  /* set non blocking, the POSIX way */

  flags = fcntl(plug,F_GETFL,0);
  flags |= O_NONBLOCK;
  result = fcntl(plug,F_SETFL,flags);

  if(config_entries.debug && outfile)
    {
      fprintf(outfile,
	      "DEBUG: wingate_bindsocket() plug = %d set non blocking %d\n",
	      plug, result);
    }

  wingate[found_slot].socket = plug;
  wingate[found_slot].state = WINGATE_CONNECTING;
  strncpy(wingate[found_slot].user,user,MAX_USER-1);
  strncpy(wingate[found_slot].host,host,MAX_HOST-1);
  strncpy(wingate[found_slot].nick,nick,MAX_NICK-1);
  (void)memset(&wingate[found_slot].socketname, 0, sizeof(struct sockaddr_in));

  (void)setsockopt(plug,SOL_SOCKET,SO_REUSEADDR,(char *)&optval,
		   sizeof(optval));

  wingate[found_slot].socketname.sin_family = AF_INET;
  wingate[found_slot].socketname.sin_port = htons (23);

  if ( !(remote_host = gethostbyname (host)) )
    {
      (void)close(plug);
      wingate[found_slot].socket = INVALID;
      return (INVALID);
    }
  (void) memcpy ((void *) &wingate[found_slot].socketname.sin_addr,
		(void *) remote_host->h_addr,
		remote_host->h_length);

  /* connect socket */

  result = connect(plug, (struct sockaddr *) &wingate[found_slot].socketname,
		   sizeof(struct sockaddr_in));
  return (plug);
}
#endif

#ifdef DETECT_SOCKS

/*
** socks_bindsocket()
**   Sets up a socket and connects to the given host
*/
int socks_bindsocket(char *nick,char *user,char *host,char *ip)
{
  int plug;
  int result;
  struct hostent *remote_host;
  int flags;
  int optval;
  int i;
  int found_slot = -1;
  placed;

  for(i=0;i<MAXSOCKS;i++)
    {
      if(socks[i].socket == INVALID)
	{
	  found_slot = i;
	  break;
	}
    }

  if(found_slot == INVALID)
    return INVALID;

  /* open an inet socket */
  if ((plug = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      printf ("error: can't assign fd for socket\n");
      return (INVALID);
    }

  /* set non blocking, the POSIX way */

  flags = fcntl(plug,F_GETFL,0);
  flags |= O_NONBLOCK;
  result = fcntl(plug,F_SETFL,flags);

  if(config_entries.debug && outfile)
    {
      fprintf(outfile,
	      "DEBUG: socks_bindsocket() plug = %d set non blocking %d\n",
	      plug, result);
    }

  socks[found_slot].socket = plug;
  socks[found_slot].state = SOCKS_CONNECTING;
  strncpy(socks[found_slot].user,user,MAX_USER-1);
  strncpy(socks[found_slot].host,host,MAX_HOST-1);
  strncpy(socks[found_slot].nick,nick,MAX_NICK-1);
  (void)memset(&socks[found_slot].socketname, 0, sizeof(struct sockaddr_in));

  (void)setsockopt(plug,SOL_SOCKET,SO_REUSEADDR,(char *)&optval,
		   sizeof(optval));

  socks[found_slot].socketname.sin_family = AF_INET;
  socks[found_slot].socketname.sin_port = htons (1080);

  if ( !(remote_host = gethostbyname (host)) )
    {
      (void)close(plug);
      socks[found_slot].socket = INVALID;
      return (INVALID);
    }
  (void) memcpy ((void *) &socks[found_slot].socketname.sin_addr,
		(void *) remote_host->h_addr,
		remote_host->h_length);

  /* connect socket */

  result = connect(plug, (struct sockaddr *) &socks[found_slot].socketname,
		   sizeof(struct sockaddr_in));
  return (plug);
}
#endif

/*
** prnt()
**   Like toserv() but takes a socket number as a parameter.  This
**   Only called from this file though.
*
*
* inputs	- socket to reply on if local
* output	- NONE
* side effects	- input socket is ignored if its message meant
*		  for user on another tcm, or its message
*		  meant for a specific user on this tcm.
*
*/
void prnt(int sock, ...)
{
  char dccbuff[DCCBUFF_SIZE];
  char msgbuf[MAX_BUFF];
  char *format;
  va_list va;
#ifdef DEBUGMODE
  placed;
#endif

  va_start(va,sock);

  format = va_arg(va, char *);
  vsnprintf(msgbuf, sizeof(msgbuf)-2, format, va);
  if (msgbuf[strlen(msgbuf)-1] != '\n') strncat(msgbuf, "\n\0", 2);
  if(route_entry.to_nick[0])
    {
      (void)sprintf(dccbuff,":%s@%s %s@%s %s",
		    route_entry.to_nick,
		    route_entry.to_tcm,
		    config_entries.dfltnick,
		    config_entries.dfltnick,
		    msgbuf);

      send(sock, dccbuff, strlen(dccbuff), 0);
    }
  else
    {
      send(sock, msgbuf, strlen(msgbuf), 0);
    }

  if(config_entries.debug)
    {
      (void)printf("-> %s",msgbuf);	/* - zaph */
      if(outfile)
	(void)fprintf(outfile,"%s",msgbuf);
    }
 va_end(va);
}


/*
 * toserv
 *
 * inputs	- msg to send directly to server
 * output	- NONE
 * side effects	- server executes command.
 */

void toserv(char *format, ... )
{
  char msgbuf[MAX_BUFF];
  va_list va;
#ifdef DEBUGMODE
  placed;
#endif
  
  va_start(va,format);

  if (connections[0].socket != INVALID)
    {
      vsnprintf(msgbuf,sizeof(msgbuf),format, va);
      send(connections[0].socket, msgbuf, strlen(msgbuf), 0);
    }
#ifdef DEBUGMODE
  printf("->%s", msgbuf);
#endif

  va_end(va);
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
  char tcm_msg[MAX_BUFF];
  char *format;
  int i;
  int echo;
  int local_tcm = NO;	/* local tcm ? */
#ifdef DEBUGMODE
  placed;
#endif

  /* what a hack...
   * each tcm prefixes its messages sent to each user
   * with "<nick@tcmnick>" unless its a clone report, link report
   * etc. This is fine, unless its being sent to a tcm
   *
   * if its an "o:" its gonna have a "o:<user@tcmnick>" so it goes
   * straight through
   *
   * if its a '.' command, it goes straight through
   * as '.' commands are not seen elsewhere, but are directly
   * dealt with. (i.e. glines)
   *
   * if its another else and is missing the '<' it gets the tcm nick
   * prepended.
   */

  va_start(va,type);

  format = va_arg(va, char *);
  vsprintf(msgbuf, format, va);

  if(type != SEND_OPERS_PRIVMSG_ONLY)
    {
      /* If opers only message, it goes straight through */
      if((msgbuf[0] == 'o' || msgbuf[0] == 'O')
	 && msgbuf[1] == ':')
	{
	  (void)sprintf(tcm_msg,"%s\n",msgbuf);
	}
      else
	{
	  /* command prefix, goes straight through */
	  
	  if(msgbuf[0] == '.')
	    (void)sprintf(tcm_msg,"%s\n",msgbuf);
	  
	  /* Missing a leading '<', we prepend the tcmnick as <tcmnick> */
	  else if(msgbuf[0] != '<')
	    {
	      (void)sprintf(tcm_msg,"<%s> %s\n",config_entries.dfltnick,msgbuf);
	      local_tcm = YES;
	    }

	  /* anything else already has a leading "<" or "O:<" */
	  else
	    (void)sprintf(tcm_msg,"%s\n",msgbuf);
	}
    }

  echo = connections[incoming_connnum].type & TYPE_ECHO;

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
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_MOTD_ONLY:
	      if (connections[i].type & TYPE_MOTD)
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_LINK_ONLY:
	      if (connections[i].type & TYPE_LINK)
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_WARN_ONLY:
	      if (connections[i].type & TYPE_WARN)
		prnt(connections[i].socket, msgbuf );
	      break;
	      
	    case SEND_WALLOPS_ONLY:
	    case SEND_LOCOPS_ONLY:
	      if (connections[i].type & TYPE_LOCOPS)
		prnt(connections[i].socket, msgbuf );
	      break;
	      
	    case SEND_OPERS_STATS_ONLY:
	      if(connections[i].type & TYPE_STAT)
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_OPERS_ONLY:
	      if(connections[i].type & TYPE_TCM)
		prnt(connections[i].socket, "%s", tcm_msg );
	      else if(connections[i].type & (TYPE_OPER | TYPE_WARN))
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_OPERS_PRIVMSG_ONLY:
	      if((connections[i].type & TYPE_OPER) &&
		 (connections[i].set_modes & SET_PRIVMSG))
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_OPERS_NOTICES_ONLY:
	      if((connections[i].type & TYPE_OPER) &&
		 (connections[i].set_modes & SET_NOTICES))
		prnt(connections[i].socket, msgbuf );
	      break;

	    case SEND_ALL_USERS:
	      if(connections[i].type & TYPE_TCM)
		prnt(connections[i].socket, tcm_msg );
	      else
		{
		  if(local_tcm)
		    prnt(connections[i].socket, msgbuf );
		  else
		    {
		      if(connections[i].type & TYPE_PARTYLINE)
			prnt(connections[i].socket, msgbuf);
		    }
		}
	      break;

	    default:
	      break;
	    }
	}
    }
    va_end(va);
}


/*
 * Generic report
 *
 * report
 *
 * inputs	-
 * output 	- NONE
 * side effects
 */

void report(int type, int channel_send_flag, char *format,...)
{
  char msg[MAX_BUFF];
  va_list va;

  va_start(va,format);
  vsnprintf(msg, sizeof(msg)-2,format,va);

  sendtoalldcc(type,msg);

  if( channel_send_flag & config_entries.channel_report )
    {
      msg_mychannel(msg);
    }

  va_end(va);
}

time_t last_ping_time = 0;

/*
** rdpt()
**   Read incoming data off one of the sockets and process it
*/
void rdpt(void)
{
  int select_result;
  int lnth;
  int i;
  char dccbuff[DCCBUFF_SIZE];
  struct timeval server_time_out;
  static time_t clones_last_check_time=(time_t)0;	/* clone check */
  static time_t remote_tcm_socket_setup_time=(time_t)0;
  time_t cur_time;
#ifdef DEBUGMODE
  placed;
#endif

  cur_time = time((time_t *)NULL);
  last_ping_time = cur_time;

  FOREVER
    {
      FD_ZERO (&readfds);
#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
      FD_ZERO (&writefds);
#endif
      for (i=0; i<maxconns; ++i)
	if (connections[i].socket != INVALID)
	  FD_SET(connections[i].socket,&readfds);

#ifdef DETECT_WINGATE
	  for (i=0; i<MAXWINGATES;i++)
	    {
	      if(wingate[i].socket != INVALID)
		{
		  if(wingate[i].state == WINGATE_CONNECTING)
		    FD_SET(wingate[i].socket,&writefds);
		  else if( (wingate[i].state == WINGATE_READING))
		    {
		      if(cur_time > (wingate[i].connect_time + 10))
			{
			  (void)close(wingate[i].socket);
			  wingate[i].socket = INVALID;
			  wingate[i].state = 0;
			}
		      else if(cur_time > (wingate[i].connect_time + 1))
			{
			  FD_SET(wingate[i].socket,&readfds);
			}
		    }
		}
	    }
#endif

#ifdef DETECT_SOCKS
	  for (i=0; i<MAXSOCKS;i++)
	    {
	      if(socks[i].socket != INVALID)
		{
		  if(socks[i].state == SOCKS_CONNECTING)
		    FD_SET(socks[i].socket,&writefds);
		}
	    }
#endif

      if(remote_tcm_socket > 0)
	FD_SET(remote_tcm_socket,&readfds);

      if(initiated_dcc_socket > 0)
	FD_SET(initiated_dcc_socket,&readfds);

      server_time_out.tv_sec = SERVER_TIME_OUT;
      server_time_out.tv_usec = 0L;

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
      if( (select_result = select(FD_SETSIZE,
				  &readfds,
				  &writefds,
				  (fd_set *)NULL,
				  &server_time_out)) > 0)
#else
      if( (select_result = select(FD_SETSIZE,
				  &readfds,
				  (fd_set *)NULL,
				  (fd_set *)NULL,
				  &server_time_out)) > 0 )
#endif
	{
	  if(remote_tcm_socket > 0)
	    if( FD_ISSET(remote_tcm_socket, &readfds) )
	      connect_remote_tcm(INVALID);

	  if(initiated_dcc_socket > 0)
	    if( FD_ISSET(initiated_dcc_socket, &readfds) )
	      {
		connect_remote_client(initiated_dcc_nick,
				      initiated_dcc_user,
				      initiated_dcc_host,
				      initiated_dcc_socket);
		initiated_dcc_socket = (-1);
	      }

#ifdef DETECT_WINGATE
	  for (i=0; i<MAXWINGATES;i++)
	    {
	      char buffer[256];
	      int nread;
	      char *p;

	      if(wingate[i].socket != INVALID)
		{
		  if(FD_ISSET(wingate[i].socket, &writefds))
		    {
		      struct stat buf;

		      if(fstat(wingate[i].socket,&buf) < 0)
			 {
			   (void)close(wingate[i].socket);
			   wingate[i].state = 0;
			   wingate[i].socket = INVALID;
			 }
		      else
			{
			  wingate[i].state = WINGATE_READING;
			  wingate[i].connect_time = cur_time;
			}
		    }		
		}

	      if(wingate[i].socket != INVALID)
		{
		  int open_wingate = NO;

		  if (FD_ISSET(wingate[i].socket, &readfds))
		    {
		      nread = read(wingate[i].socket,buffer,256);
		      if(nread > 0)
			{
			  buffer[nread] = '\0';
			  if( (p = strchr(buffer,'W')) )
			    {
			      if(strncasecmp(p,"wingate>",9) == 0)
				{
				  open_wingate = YES;
				}
			    }
			  else if( (p = strchr(buffer,'T')) )
			    {
			      if(strncasecmp(p,
                   "Too many connected users - try again later",42)==0)
				{
				  open_wingate = YES;
				}
			    }

			  if(open_wingate)
			    {
			      report_open_wingate(i);
			      (void)close(wingate[i].socket);
			      wingate[i].socket = INVALID;
			      wingate[i].state = 0;
			    }
			}
		    }
		}
	    }
#endif

#ifdef DETECT_SOCKS
	  for (i=0; i<MAXSOCKS;i++)
	    {
	      if(socks[i].socket != INVALID)
		{
		  if(FD_ISSET(socks[i].socket, &writefds))
		    {
		      struct stat buf;
		      if(fstat(socks[i].socket,&buf) > 0) report_open_socks(i);
		      (void)close(socks[i].socket);
		      socks[i].state = 0;
		      socks[i].socket = INVALID;
		    }
		}
	    }
#endif

	  for (i=0; i<maxconns; ++i)
	    {
	      if (connections[i].socket != INVALID)
		{
		 /* Timeouts should only be for TCMs, not unregistered opers
		     -pro */
		  if( (connections[i].type & TYPE_PENDING & TYPE_TCM) &&
		      ((connections[i].last_message_time + TCM_REMOTE_TIMEOUT)
		       < time((time_t *)NULL)) )
		    {
		      closeconn(i);
		      continue;
		    }

		  if( FD_ISSET(connections[i].socket, &readfds))
		    {
		      incoming_connnum = i;

		      lnth =recv(connections[i].socket,connections[i].buffend,
				 1,0);

		      if (lnth == 0)
			{
			  if (i == 0)
			    linkclosed("EOF from server");
			  else
			    closeconn(i);
			  continue;
			}

		      if (*connections[i].buffend == '\n' ||
			  *connections[i].buffend == '\r' ||
			  connections[i].buffend - connections[i].buffer
			  == BUFFERSIZE -1)
			{
			  *connections[i].buffend = '\0';
			  connections[i].buffend = connections[i].buffer;
			  if (*connections[i].buffer)
                          {
			    if (i == 0)
                            {
			      serverproc();
			    } else
			      {
				if( (connections[i].type & TYPE_TCM) &&
				    (connections[i].type & TYPE_PENDING))
                                {
				  connect_remote_tcm(i);
				} else
				  {
				    connections[i].last_message_time =
				      time((time_t *)NULL);
				    dccproc(i);
				  }
			      }
			  continue;
			}
		      } else
                      {
			++connections[i].buffend;
                      }
		    }
		}
	    }

#ifdef SERVICES
	  check_services();
#endif
	  if ((clones_last_check_time + CLONE_CHECK_TIME) < cur_time)
	    {
	      check_clones();
	      clones_last_check_time = cur_time;
	    }

	  if ((last_ping_time + PING_OUT_TIME) < cur_time)
	    {
	      sendtoalldcc(SEND_ALL_USERS,"PING time out on server\n");
	      log_problem("rdpt()","ping time out");
	      linkclosed("ping time out");
	    }

	  if ( (remote_tcm_socket < 0) && (config_entries.tcm_port > 1024) &&
	      (remote_tcm_socket_setup_time + REMOTE_TCM_CHECK_TIME) < cur_time)
	    {
	      sendtoalldcc(SEND_OPERS_ONLY, 
			   "Attempting to init remote tcm listen socket\n");
	      init_remote_tcm_listen();
	      remote_tcm_socket_setup_time = cur_time;
	    }
	}
      else
	{
	  /* if select_result == 0, timer expired */
	  if(select_result == 0)
	    {
	      if ((last_ping_time + PING_OUT_TIME) < cur_time)
		{
		  sendtoalldcc(SEND_ALL_USERS,"PING time out on server\n");
		  log_problem("rdpt()","ping time out");
		  linkclosed("ping time out");
		}
	    }
	  else if(select_result < 0)
	    {
	      (void)sprintf(dccbuff,"select error %d",errno);
	      log_problem("rdpt()",dccbuff);
	      linkclosed("select error");
	    }
	}
    }
}


#ifdef DETECT_WINGATE
static void report_open_wingate(int i)
  {
    if(config_entries.debug && outfile)
      {
	fprintf(outfile, "Found wingate open\n");
      }

      suggest_kill_kline(R_WINGATE,
			 wingate[i].nick,
			 wingate[i].user,
			 wingate[i].host,
			 NO,
			 NO);

      log("Open Wingate %s!%s@%s\n",
	  wingate[i].nick, wingate[i].user, wingate[i].host);
  }

#endif

#ifdef DETECT_SOCKS
static void report_open_socks(int i)
  {
    if(config_entries.debug && outfile)
      {
	fprintf(outfile, "Found open socks proxy\n");
      }

    suggest_kill_kline(R_SOCKS,
		       socks[i].nick,
		       socks[i].user,
		       socks[i].host,
		       NO,
		       NO);

    log("Open socks proxy %s\n",socks[i].host);
  }
#endif

#ifdef SERVICES
/*
 * check_services
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	-
 */

static void check_services(void)
{
  time_t cur_time;
#ifdef DEBUGMODE
  placed;
#endif

  cur_time = time((time_t *)NULL);

  if((services.last_checked_time + SERVICES_CHECK_TIME) < cur_time )
     {
       services.last_checked_time = cur_time;
       route_entry.to_nick[0] = '\0';
       route_entry.to_tcm[0] = '\0';
       route_entry.from_nick[0] = '\0';
       route_entry.from_tcm[0] = '\0';

       privmsg(SERVICES_NICK,"clones %d\n", SERVICES_CLONE_THRESHOLD );

#ifdef SERVICES_DRONES
       privmsg(SERVICES_NICK,"drones %s\n", config_entries.rserver_name);
#endif

     }
}

/*
 * on_services_notice
 *
 * inputs	- body from message sent to us from service.us
 * output	- NONE
 * side effects	- reports of global cloners
 */

static void on_services_notice(char *body)
{
  char *parm1;
  char *parm2;
  char *parm3;
  char userathost[MAX_HOST];
  int  identd;
  char *p;
  char *user, *host;
#ifdef DEBUGMODE
  placed;
#endif

  while(*body == ' ')
    body++;

  if( !(parm1 = strtok(body," ")) )
    return;

  if( !(parm2 = strtok((char *)NULL," ")) )
    return;

  if( !(parm3 = strtok((char *)NULL,"")) )
    return;

#ifdef SERVICES_DRONES
  /* kludge. but if there is a ! seen in parm1, its a drone report */

  if( (p = strchr(parm1,'!' )) )
    {
      *p = '\0';
      p++;

      if( !(host = strchr(p,'@')) )
	return;
      host++;

      if( (p = strchr(host,' ')) )
	*p = '\0';

      report(SEND_ALL_USERS, CHANNEL_REPORT_DRONE,
	     "%s reports drone %s\n",
	     SERVICES_NAME,
	     parm1);

      if(config_entries.drones_act[0])
	toserv("%s *@%s :%s\n",
	       config_entries.drones_act,
	       host,
	       config_entries.drones_reason);

      log("%s reports drone %s [%s]\n", SERVICES_NAME, parm1, host);
      return;
    }
	
#endif

  if( strstr(parm3,"users") )
    {
      strncpy(services.cloning_host,parm1,MAX_HOST-1);
      if(!services.last_cloning_host[0])
        strncpy(services.last_cloning_host,parm1,MAX_HOST-1);
      strncpy(services.user_count,parm3,SMALL_BUFF-1);
      services.kline_suggested = NO;
      return;
    }

  if((strcasecmp("on",parm2) == 0) &&
     (strcasecmp(config_entries.rserver_name,parm3) == 0))
    {
      if(strcmp(services.last_cloning_host,services.cloning_host) != 0)
        services.clones_displayed = 0;

      strncpy(services.last_cloning_host,services.cloning_host,MAX_HOST-1);

      if(services.clones_displayed == 3)
	{
	  return;
	}
      services.clones_displayed++;

      strncpy(userathost,services.cloning_host,sizeof(userathost));

      if ( (host = strchr(userathost, '@')) )
	{
	  user = userathost;
	  *host = '\0';
	  host++;
	}
      else
	return;

      if (!okhost(user, host))
	{
	  report(SEND_ALL_USERS,
		 CHANNEL_REPORT_SCLONES,
		 "%s reports %s cloning %s nick %s\n",
		 SERVICES_NAME,
		 services.user_count,
		 services.cloning_host,
		 parm1);
	}

      if(services.kline_suggested == NO)
	{
	  char user_host[MAX_HOST+1];

	  strncpy(userathost,services.cloning_host,MAX_HOST);

	  /* strtok is going to destroy the original userathost,
	     so save a copy for our own uses */

	  strncpy(user_host,userathost,MAX_HOST);

	  if( !(user = strtok(userathost,"@")) )	
	    return;

	  identd = YES;
	  if(*user == '~')
	    identd = NO;

	  if( !(host = strtok((char *)NULL,"")) )
	    return;

	  if( (okhost(user,host)) || (isoper(user,host)))
	    {
	      return;
	    }

	  suggest_kill_kline(R_SCLONES,
			     "",
			     user,
			     host,
			     NO,
			     identd);

	  services.kline_suggested = YES;
	}
    }
  else
    services.clones_displayed = 0;
}

#endif

/*
 * serverproc()
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- process server message
 */

static void serverproc(void)
{
  char *buffer = connections[0].buffer;
  char *p;
  char *source;
  char *fctn;
  char *body = NULL;

  if(*buffer == ':')
    {
      source = buffer+1;
      if( (p = strchr(buffer,' ')) )
	*p = '\0';
      p++;
      fctn = p;

      if( (p = strchr(fctn,' ')) )
	{
	  *p = '\0';
	  p++;
	  body = p;
	}
    }
  else
    {
      source = "";

      fctn = buffer;

      if( (p = strchr(fctn,' ')) )
	{
	  *p = '\0';
	  p++;
	  body = p;
	}
    }

  if(config_entries.debug && outfile)
    {
      fprintf(outfile, ">source=[%s] fctn=[%s] body=[%s]\n",
	      source, fctn, body);	/* - zaph */
    }
  proc(source,fctn,body);
}

/*
** signon()
**   Send a USER and a NICK string to the server.
*    also send PASS if the tcm has a password in the S line
**   Parameters: None
**   Returns: void
**   PDL:
**     What it said 4 lines above. :)  Also, initialize the internal
**     variable holding tcm's current nickname.
*/
void signon()
{
#ifdef DEBUGMODE
    placed;
#endif

    connections[0].buffend = connections[0].buffer;
    if (!*mynick)
      strcpy (mynick,config_entries.dfltnick);

    if( config_entries.server_pass[0] )
      toserv("pass %s\n", config_entries.server_pass);

    toserv("user %s %s %s :%s\n",
	   config_entries.username_config,
	   ourhostname,
	   config_entries.server_name,
	   config_entries.ircname_config);

    toserv("nick %s\n", mynick);
}

void do_init(void)
{
#ifdef DEBUGMODE
  placed;
#endif

  toserv("VERSION\n");

  if(config_entries.defchannel_key[0])
    join(config_entries.defchannel,config_entries.defchannel_key); 
  else
    join(config_entries.defchannel,(char *)NULL);

  initopers();
  oper();
  inithash();
}

/*
** linkclosed()
**   Called when an error has causes the server to close our link.
**   Parameters: None
**   Returns: void
**   PDL:
**     Close the old dead socket.  If we haven't already reconnected
**     5 times, wait 5 seconds, reconnect to the server, and re-signon.
*/
static void linkclosed(char *reason)
{
#ifdef DEBUGMODE
  placed;
#endif

  (void)close(connections[0].socket);
  log_problem("linkclosed()", reason);

  amianoper = NO;

  log_problem("linkclosed()","sleeping 30");
  sleep(30);
  connections[0].socket = bindsocket(serverhost);
  if (connections[0].socket == INVALID)
    {
      log_problem("linkclosed()","invalid socket quitting");
      quit = YES;
      return;
    }
  signon();
}

/*
** makeconn()
**   Makes another connection
*/
char makeconn(char *hostport,char *nick,char *userhost)
{
  int  i;		/* index variable */
  char *p;		/* scratch pointer used for parsing */
  char *type;
  char *user;
  char *host;
#ifdef DEBUGMODE
  placed;
#endif

  for (i=1; i<MAXDCCCONNS+1; ++i)
    if (connections[i].socket == INVALID)
      {
	if (maxconns < i+1)
	  maxconns = i+1;
	break;
      }

  if (i > MAXDCCCONNS)
    return 0;

  connections[i].socket = bindsocket(hostport);

  if (connections[i].socket == INVALID)
    return 0;
  connections[i].set_modes = 0;

  connections[i].buffer = (char *)malloc(BUFFERSIZE);
  if(!connections[i].buffer)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in makeconn\n");
      gracefuldie(0, __FILE__, __LINE__);
    }

  connections[i].buffend = connections[i].buffer;
  strncpy(connections[i].nick,nick,MAX_NICK-1);
  connections[i].nick[MAX_NICK-1] = '\0';

  if( (p = strchr(userhost,'@')) )
    {
      user = userhost;
      *p = '\0';
      p++;
      host = p;
    }
  else
    {
      host = userhost;
      user = "*";
    }

  if( (p = strchr(host,' ')) )
    *p = '\0';

  strncpy(connections[i].user,user,MAX_USER-1);
  connections[i].user[MAX_USER-1] = '\0';
  strncpy(connections[i].host,host,MAX_HOST-1);
  connections[i].host[MAX_HOST-1] = '\0';
  connections[i].type = 0;
  connections[i].type |= isoper(user,host);
  

/* I think the credit for this idea of OPERS_ONLY is from phisher */
/* my hack though. blame me. - Dianora */

#ifdef OPERS_ONLY
  if(!(connections[i].type & TYPE_OPER))
    {
      prnt(connections[i].socket,
	   "Sorry, only opers may use this service.\n");
      (void)close(connections[i].socket);
      connections[i].socket = INVALID;
      connections[i].nick[0] = '\0';
      connections[i].registered_nick[0] = '\0';
      connections[i].user[0] = '\0';
      connections[i].type = 0;
      (void)free(connections[i].buffer);
      return 0;
    }
#else
  if( !(connections[i].type & TYPE_OPER) && isbanned(user,host)) /* allow opers on */
    {
      prnt(connections[i].socket,
	   "Sorry, you are banned.\n");
      (void)close(connections[i].socket);
      connections[i].socket = INVALID;
      connections[i].nick[0] = '\0';
      connections[i].registered_nick[0] = '\0';
      connections[i].user[0] = '\0';
      connections[i].type = 0;
      (void)free(connections[i].buffer);
      return 0;
    }
#endif

  connections[i].last_message_time = time((time_t *)NULL);

  toserv("%s(%s)\n",VERSION,SERIALNUM);

  print_motd(connections[i].socket);

  prnt(connections[i].socket,"current clone action: %s\n",
       config_entries.clone_act);

  type = "User";
  if(connections[i].type & TYPE_OPER)
    type = "Oper";
  if(connections[i].type & TYPE_TCM)
    type = "Tcm";

  report(SEND_ALL_USERS,
	 CHANNEL_REPORT_ROUTINE,
	 "%s %s (%s@%s) has connected\n",
	 type,
	 connections[i].nick,
	 connections[i].user,
	 connections[i].host);

  prnt(connections[i].socket,
       "Connected.  Send '.help' for commands.\n");
  return 1;
}

/*
 * add_connection
 *
 * inputs	- socket
 *		- tcm_entry
 * output	- either INVALID or index into connections
 * side effects	-
 */

int add_connection(int sock,int tcm_entry)
{
  int i;
#ifdef DEBUGMODE
  placed;
#endif

  for( i=1; i<MAXDCCCONNS+1; ++i )
    {
      if(connections[i].socket == INVALID)
	{
	  if(maxconns < i+1)
	    maxconns = i+ 1;
	  break;
	}
    }
  if(i > MAXDCCCONNS)
    return(INVALID);

  connections[i].buffer = (char *)malloc(BUFFERSIZE);
  if(!connections[i].buffer)
    {
      sendtoalldcc(SEND_ALL_USERS, 
		   "Ran out of memory in add_connection\n");
      gracefuldie(0, __FILE__, __LINE__);
    }

  connections[i].buffend = connections[i].buffer;

  strncat(connections[i].nick,tcmlist[tcm_entry].theirnick,MAX_NICK-1);
  
  connections[i].nick[MAX_NICK-1] = '\0';
  connections[i].user[0] = '\0';

  strncpy(connections[i].host,tcmlist[tcm_entry].host,MAX_HOST-1);
  connections[i].user[MAX_HOST-1] = '\0';

  connections[i].socket = sock;
  connections[i].type = TYPE_TCM|TYPE_OPER|TYPE_REGISTERED;
  return(i);
}

/*
 * closeconn()
 *
 * inputs	- connection number
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */

void closeconn(int connnum)
{
  int i;
  char *type;
#ifdef DEBUGMODE
  placed;
#endif

  if (connections[connnum].socket != INVALID)
    close(connections[connnum].socket);

  if(connections[connnum].buffer)
    free (connections[connnum].buffer);

  connections[connnum].buffer = (char *)NULL;
  connections[connnum].socket = INVALID;

  if (connnum + 1 == maxconns)
    {
      for (i=maxconns;i>0;--i)
	if (connections[i].socket != INVALID)
	  break;
      maxconns = i+1;
    }

  type = "User";
  if(connections[connnum].type & TYPE_OPER)
    type = "Oper";
  if(connections[connnum].type & TYPE_TCM)
    type = "Tcm";

  if(connections[connnum].type & TYPE_PENDING)
    {
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_ROUTINE,
	     "Failed tcm connect from %s@%s\n",
	     connections[connnum].user,
	     connections[connnum].host);
    }
  else
    {
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_ROUTINE,
	     "%s %s (%s@%s) has disconnected\n",
	     type,
	     connections[connnum].nick,
	     connections[connnum].user,
	     connections[connnum].host);
    }

  connections[connnum].user[0] = '\0';
  connections[connnum].host[0] = '\0';
  connections[connnum].nick[0] = '\0';
  connections[connnum].registered_nick[0] = '\0';
}

/*
 * privmsgproc()
 * 
 * inputs	- nick
 * 		- user@host string
 * 		- message body
 * output	- none
 * side effects	- 
 */
void privmsgproc(char *nick,char *userhost,char *body)
{
  int token;
  char *user;	/* user portion */
  char *host;	/* host portion */
  char *p;
  char *param1;
#ifdef DEBUGMODE
  placed;
#endif

  user = userhost;
  if( !(p = strchr(userhost,'@')) )
    return;

  *p = '\0';
  p++;
  host = p;

  if( !(param1 = strtok(body," ")) )
    return;

  token = get_token(param1);

  if(!isoper(user,host))
    {
      notice(nick,"You aren't an oper");
      return;
    }

  switch(token)
    {
    case K_CHAT:
      if(initiated_dcc_socket > 0)
	{
	  if((initiated_dcc_socket_time + 60) < time((time_t *)NULL) )
	    {
	      (void)close(initiated_dcc_socket);
	      initiated_dcc_socket = -1;
	      initiate_dcc_chat(nick,user,host);
	    }
	  else
	    notice(nick,"Unable to dcc chat right now, wait a minute");
	}
      else
	initiate_dcc_chat(nick,user,host);
      break;

    case K_CLONES:
      report_clones(0);
      break;

    default:
      notice(nick,"I don't understand");
      break;
    }
}

/*
 * initiate_dcc_chat
 * 
 * inputs	- nick
 * 		- host
 * output	- none
 * side effects	- initiate a dcc chat =to= a requester
 */

#define LOWEST_DCC_PORT 1025
#define HIGHEST_DCC_PORT 3050

static void initiate_dcc_chat(char *nick,char *user,char *host)
{
  int dcc_port;				/* dcc port to use */
  struct sockaddr_in socketname;
  int result = -1;

  notice(nick,"Chat requested");
  strncpy(initiated_dcc_nick,nick,MAX_NICK);
  strncpy(initiated_dcc_user,user,MAX_USER);
  strncpy(initiated_dcc_host,host,MAX_HOST);

  if( (initiated_dcc_socket = socket(PF_INET,SOCK_STREAM,6)) < 0)
    {
      fprintf(stderr,
	      "Error on open()\n");
      notice(nick,"Error on open");
      return;
    }

  for(dcc_port = LOWEST_DCC_PORT; dcc_port < HIGHEST_DCC_PORT; dcc_port++ )
    {
      memset(&socketname,0, sizeof(struct sockaddr));
      socketname.sin_family = AF_INET;
      socketname.sin_addr.s_addr = INADDR_ANY;
      socketname.sin_port = htons(dcc_port);

      if( (result = bind(initiated_dcc_socket,(struct sockaddr *)&socketname, 
	      sizeof(socketname)) < 0) )
	{
	  continue;
	}
      break;
    }

  if(result < 0)
    {
      (void)close(initiated_dcc_socket);
      initiated_dcc_socket = (-1);
      (void)fprintf(stderr,
		    "Can't bind result = %d errno = %d\n",result, errno);
      notice(nick,"Can't dcc chat");
      return;
    }

  if ( listen(initiated_dcc_socket,4) < 0 )
    {
      (void)close(initiated_dcc_socket);
      initiated_dcc_socket = (-1);
      (void)fprintf(stderr,"Can't listen\n");
      notice(nick,"Can't dcc chat");
      return;
    }

  privmsg(nick,"\001DCC CHAT chat %lu %d\001\n",
      local_ip(),dcc_port);

  if(config_entries.debug && outfile)
    {
      (void)fprintf(outfile, "DEBUG: initiated_dcc_socket = %d\n",
		    initiated_dcc_socket);
    }

  initiated_dcc_socket_time = time((time_t *)NULL);
}

/* 
 * local_ip()
 * 
 * inputs		- NONE
 * output		- ip of local host
 * side effects	- NONE
 */

static unsigned long local_ip(void)
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
 * already_have_tcm
 *
 * inputs	- new nick being introduced
 * output	- YES if this tcm nick is already linked to me
 * 		  NO if this tcm nick is not already linked to me
 * side effects	- NONE
 */
int already_have_tcm(char *tcmnick)
{
  int i;
#ifdef DEBUGMODE
  placed;
#endif

  if(config_entries.debug && outfile)
    {
      fprintf(outfile, "already_have_tcm() tcmnick = [%s]\n", tcmnick );
    }

    for (i=1;i<maxconns;++i)
      if (connections[i].socket != INVALID)
	{
	  if(connections[i].type & TYPE_TCM)
	    {
	      if(config_entries.debug && outfile)
		{
		  fprintf(outfile, "connections[%d].nick [%s] tcmnick [%s]\n",
			  i,connections[i].nick, tcmnick );
		}
	      if(strcasecmp(connections[i].nick, tcmnick) == 0)
		{
		  if(config_entries.debug && outfile)
		    {
		      fprintf(outfile, "returning YES\n");
		    }
		  return(YES);
		}
	    }
	}

  return(NO);
}


/*
** proc()
**   Parse server messages based on the function and handle them.
**   Parameters:
**     source - nick!user@host or server host that sent the message
**     fctn - function for the server msgs (e.g. PRIVMSG, MODE, etc.)
**     param - The remainder of the server message
**   Returns: void
**   PDL:
**     If the source is in nick!user@host format, split the nickname off
**     from the userhost.  Split the body off from the parameter for the
**     message.  The parameter is generally either our nickname or the
**     nickname directly affected by this message.  You can kind of figure
**     the rest of the giant 'if' statement out.  Occasionally we need to
**     parse additional parameters out of the body.  To find out what all
**     the numeric messages are, check out 'numeric.h' that comes with the
**     server code.  ADDED: watch out for partial PRIVMSGs received from the
**     server... hold them up and make sure to stay synced with the timer
**     signals that may be ongoing.
*/
static void proc(char *source,char *fctn,char *param)
{
    char *userhost, *body;
    char *modeparms;
    int numeric;		/* if its an numeric */
    char *p;
    char *q;
#ifdef DEBUGMODE
    placed;
#endif

    if ( (userhost = strchr(source, '!') ) )
      {
	*(userhost++) = '\0';
	if (*userhost == '~')
	  ++userhost;
      }

    if ( (body = strchr(param,' ')) )
      {
	*(body++) = '\0';
	while (*body == ' ') ++body;	/* ircd-comstud wants to make it hard for us. -pro */
	if (*body == ':')
	  ++body;
      }

    if (!strcmp(fctn,"PRIVMSG"))
      {
	if(strcasecmp(param,mynick) == 0)
	   {
	     if(body[0] == '\001')	/* its a DCC something */
	       onctcp(source, userhost, body);
	     else if(body[0] == '.')
	       privmsgproc(source,userhost,body+1);
	     else
	       {
		 sendtoalldcc(SEND_OPERS_PRIVMSG_ONLY,
			      "privmsg from %s>%-.400s\n",
			      source,body);
	       }
	   }
      }
    else if (!strcmp(fctn,"PING"))
      {
	last_ping_time = time((time_t *)NULL);
        toserv("PONG %s\n", param);
      }
    else if (!strcmp(fctn,"ERROR"))
      {
	if (!wldcmp("*closing*",param))
	  {
	    if (!wldcmp("*nick coll*",body))
	      onnicktaken();
	    linkclosed("*closing*");
	  }
      }
    else if (!strcmp(fctn,"KILL"))
      {
        if (strchr(source,'.'))
	  {
	    onnicktaken();
            linkclosed("KILL");
	  }
        else
	  {
	    quit = YES;
	  }
      }
    else if ( !(strcmp(fctn,"WALLOPS")) )
      {
	wallops(source, param, body);
      }
    else if ( !(strcmp(fctn,"JOIN")) )
      {
	onjoin(source, param);
      }
    else if ( !(strcmp(fctn,"KICK")) )
      {
        if ( (modeparms = strchr(body,' ')) )    /* 2.8 fix */
          *modeparms = '\0';
        onkick(body,param);
      }
    else if ( !strcmp(fctn,"NICK"))
      {
	onnick(source,param);
      }
    else if ( !strcmp(fctn, "I-line" ))
      {
	ilinemask(body);
      }
    else if (!strcmp(fctn,"NOTICE"))
      {
	if(!strcasecmp(source,config_entries.rserver_name))
	  {
	    if(!strncmp(body,"*** Notice -- ",14))
	      onservnotice(body+14);
	  }
#ifdef SERVICES
	else if(strcasecmp(source,SERVICES_NAME) == 0)
	  {
	    on_services_notice(body);
	  }
#endif
      }

    if(isdigit(fctn[0]) && isdigit(fctn[1]) && isdigit(fctn[2]))
      numeric = atoi(fctn);
    else
      numeric = (-1);

    switch(numeric)
      {
      case 433:
	onnicktaken();
	break;
      case  451:	/* "You have not registered"*/
	linkclosed("Not registered");
	break;
      case 474: case 471: case 475: case 473:
	*(strchr(body,' ')) = '\0';
        cannotjoin(body);
	break;
      case 001:
	if (!amianoper)
	  do_init();
	else
	  send_umodes(mynick);
	break;
      case 004:
	p = body;
	if(*p == ':')
	  p++;

	if( (q = strchr(p, ' ')) )
	  *q = '\0';

	strncpy(config_entries.rserver_name, p, MAX_CONFIG );
	q++;

	if( (p = strstr(q,"hybrid")) )
	  {
	    config_entries.hybrid = YES;

	    p += 7;
	    if(*p == '5')
	      config_entries.hybrid_version = 5;
	    else if(*p == '6')
	      config_entries.hybrid_version = 6;
	    else if(*p == '7')
	      config_entries.hybrid_version = 7;
	  }
	break;

      case 381:		/* You have entered ... */
	amianoper = YES;
	oper_time = time(NULL);
	send_umodes(mynick);
	break;
      case 204:		/* RPL_TRACEOPERATOR */
      case 205:		/* RPL_TRACEUSER */
	ontraceuser(body);
	break;
      case 209:		/* RPL_TRACECLASS */
        ontraceclass();
	break;
      case 215:
	on_stats_i(body);
	break;
      case 216:
	on_stats_k(body);
	break;
      case 243:
	on_stats_o(body);
	break;
      case 219:
	break;
      case 351:
	/* version_reply(body); */
	break;
      case 464:
      case 491:		/* Can't oper! */
	linkclosed("Can't oper");
	break;
      case 223: /* stats E */
      case 224:	/* stats F */
	on_stats_e(body);
	break;
      default:
	break;
      }
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

  toserv("QUIT :Woo hoo!  TCM crash!\n");
  
  if(sig != SIGTERM )
    abort();
  exit(1);
}

/*
 * reload_user_list()
 *
 * Thanks for the idea garfr
 *
 * inputs - signal number 
 * output - NONE
 * side effects -
 *	       reloads user list without having to restart tcm
 *
 */

void reload_user_list(int sig)
{
  if(sig != SIGHUP)	/* should never happen */
    return;

  clear_userlist();
  initopers();
  load_userlist();
  load_prefs();
  inithash();
  sendtoalldcc(SEND_ALL_USERS, "*** Caught SIGHUP ***\n");
}

/*
 * wallops()
 * inputs       - source, params, body as char string pointers
 * outputs      - sends messages to appropriate DCC users
 * side effects -
 */

static void wallops(char *source, char *params, char *body)
{
  if (!strcmp(params+1, "WALLOPS"))
    sendtoalldcc(SEND_WALLOPS_ONLY,
		 "WALLOPS %s ->  %s\n",
		 source, body[0] == '-' ? body+2 : body);
  else if (!strcmp(params+1, "LOCOPS"))
    sendtoalldcc(SEND_LOCOPS_ONLY,
		 "LOCOPS %s ->  %s\n",
		 source, body[0] == '-' ? body+2 : body);
  else if (!strcmp(params+1, "OPERWALL"))
    sendtoalldcc(SEND_WALLOPS_ONLY,
		 "OPERWALL %s ->  %s\n",
		 source, body[0] == '-' ? body+2 : body);
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
int main(argc,argv)
int argc;
char *argv[];
{
  int i;

  init_hash_tables();		/* clear those suckers out */
  init_tokenizer();		/* in token.c */
  init_userlist();

#ifdef SERVICES
  services.last_checked_time = time((time_t *)NULL);
#endif

#ifdef DEBUGMODE		/* initialize debug list */
  for(i=0;i<16;++i) placed;
  i=0;
#endif

  if(argc < 2)
    load_config_file(CONFIG_FILE);
  else
    load_config_file(argv[1]);

  load_prefs();

  strcpy(serverhost,config_entries.server_config); /* Load up desired server */

  for (i=0;i<MAXDCCCONNS+1;++i)
    {
      connections[i].socket = INVALID;
      connections[i].user[0] = '\0';
      connections[i].host[0] = '\0';
      connections[i].nick[0] = '\0';
      connections[i].registered_nick[0] = '\0';
    }

  srand(time(NULL));	/* -zaph */
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

  if(!config_entries.debug)
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
      if( !(outfile = fopen("tcm.pid","w")) )
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

  signon();
  amianoper = NO;
  startup_time = time(NULL);
  init_allow_nick();
  init_link_look_table();
  init_remote_tcm_listen();

  while(!quit)
    rdpt();

  toserv("QUIT :TCM terminating normally\n");

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
      log_problem("init_remote_tcm_list","Can't create socket for remote tcm");
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

/*
 * connect_remote_tcm()
 *
 * inputs	- INVALID or a connection number
 * output	- NONE
 * side effects	-
 */

static void connect_remote_tcm(int connnum)
{
  int i;
  struct sockaddr_in incoming_addr;
  struct hostent *host_seen;
  int addrlen;
#ifdef DEBUGMODE
  placed;
#endif

  if(remote_tcm_socket < 0)	/* extra paranoia, shouldn't be even here if this is true -db */
    return;

  if(connnum == INVALID)
    {
      for (i=1; i<MAXDCCCONNS+1; ++i)
	{
	  if (connections[i].socket == INVALID)
	    {
	      if (maxconns < i+1)
		maxconns = i+1;
	      break;
	    }
	}
      if(i > MAXDCCCONNS)
	return;

      addrlen = sizeof(struct sockaddr);
      if((connections[i].socket = accept(remote_tcm_socket,
			 (struct sockaddr *)&incoming_addr,&addrlen)) < 0 )
	{
	  fprintf(stderr,"Error in remote tcm connect on accept\n");
	  return;
	}

      host_seen = gethostbyaddr((char *)&incoming_addr.sin_addr.s_addr,
				4,AF_INET);

      connections[i].buffer = (char *)malloc(BUFFERSIZE);
      if( !connections[i].buffer )
	{
	  sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in \n");
	  gracefuldie(0, __FILE__, __LINE__);
	}

      connections[i].buffend = connections[i].buffer;
      connections[i].type = (TYPE_PENDING|TYPE_TCM);
      connections[i].last_message_time = time((time_t *)NULL);

      if(host_seen)
	strncpy(connections[i].host,(char *)host_seen->h_name,MAX_HOST-1);
      else
	strncpy(connections[i].host,
		inet_ntoa(incoming_addr.sin_addr),MAX_HOST-1);

      /* blah. with this code enabled, lusers can spam the 6800 port annoying
       * users on the tcm. I didn't have the heart to remove it completely
       * but neither have I stuck this into config.h -db
       */

#ifdef SHOW_POTENTIAL_CONNECTIONS
      (void)sprintf(dccbuff,"tcm connection from %s\n", connections[i].host); 
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_ROUTINE,
	     "tcm connection from %s\n",
	     connections[i].host);
      sendto_all_linkedbots(dccbuff);
#endif
    }
  else
    {
      if(connections[connnum].type & TYPE_PENDING)
	{
	  char *myname;
	  char *tcmname;
	  char *password;
	  int  type;

	  myname = strtok(connections[connnum].buffend," ");

	  if(myname)
	    {
	      if( !strcasecmp(myname,config_entries.dfltnick) )
		{

#ifdef SHOW_FAILED_TCM_CONNECTIONS
		  sendtoalldcc(SEND_ALL_USERS,
			       "illegal connection from %s wrong myname\n",
			       connections[connnum].host);
#endif
		  closeconn(connnum);
		  return;
		}

	      if( !(tcmname = strtok((char *)NULL," ")) )
		{
#ifdef SHOW_FAILED_TCM_CONNECTIONS
		  sendtoalldcc(SEND_ALL_USERS,
			       "illegal connection from %s missing tcmname\n",
			       connections[connnum].host);
#endif
		  closeconn(connnum);
		  return;
		}

	      if( !(password = strtok((char *)NULL,"")) )
		{
		  if( (type = islinkedbot(connnum,tcmname,password)) )
		    {
		      sendtoalldcc(SEND_ALL_USERS,
				   "%s@%s link tcm has connected\n",
				   connections[connnum].nick,
				   connections[connnum].host);
		      connections[connnum].type = type;
		    }
		  else
		    {
#ifdef SHOW_FAILED_TCM_CONNECTIONS
		      sendtoalldcc(SEND_ALL_USERS,
				   "illegal connection from %s wrong password\n",
				   connections[connnum].host);
#endif
		      closeconn(connnum);
		    }
		}
	    }
	  else
	    {
#ifdef SHOW_FAILED_TCM_CONNECTIONS
	      sendtoalldcc(SEND_ALL_USERS,
			   "illegal connection from %s\n",
			   connections[connnum].host);
#endif
	      closeconn(connnum);
	    }
	}
      else
	{
	  dccproc(connnum);
	}
    }
}

/*
 * connect_remote_client()
 * 
 * inputs	- nick
 *		- username
 *		- hostname
 *		- incoming socket
 * output	- none
 * side effects	-
 */

static void connect_remote_client(char *nick,char *user,char *host,int sock)
{
  int i;
  struct sockaddr_in incoming_addr;
  struct hostent *host_seen;
  int addrlen;
#ifdef DEBUGMODE
  placed;
#endif

  for (i=1; i<MAXDCCCONNS+1; ++i)
    {
      if (connections[i].socket == INVALID)
	{
	  if (maxconns < i+1)
	    maxconns = i+1;
	  break;
	}
    }

  if(i > MAXDCCCONNS)
    {
      notice(nick,"Max users on tcm, dcc chat rejected\n");
      (void)close(sock);
      return;
    }

  addrlen = sizeof(struct sockaddr);
  if((connections[i].socket = accept(sock,
		     (struct sockaddr *)&incoming_addr,&addrlen)) < 0 )
    {
      notice(nick,"Error in dcc chat\n");
      (void)fprintf(stderr,"Error in remote tcm connect on accept\n");
      (void)close(sock);
      return;
    }

  connections[i].buffer = (char *)malloc(BUFFERSIZE);
  if(!connections[i].buffer)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in \n");
      gracefuldie(0, __FILE__, __LINE__);
    }
  connections[i].last_message_time = time((time_t *)NULL);
  connections[i].buffend = connections[i].buffer;
  connections[i].type = TYPE_OPER;

  host_seen = gethostbyaddr((char *)&incoming_addr.sin_addr.s_addr,
			    4,AF_INET);

  if(host_seen)
    strncpy(connections[i].host,(char *)host_seen->h_name,MAX_HOST-1);
  else
    strncpy(connections[i].host,
	    inet_ntoa(incoming_addr.sin_addr),MAX_HOST-1);

  /* put a host name check in here */

  if(strcasecmp(host,(char *)host_seen->h_name) !=0 )
    {
      notice(nick,"Host name mis-match\n");
    }

  strncpy(connections[i].nick,initiated_dcc_nick,MAX_NICK);
  strncpy(connections[i].user,initiated_dcc_user,MAX_USER);

  report(SEND_ALL_USERS,
	 CHANNEL_REPORT_ROUTINE,
	 "oper dcc connection from %s!%s@%s\n",
	 nick,
	 user,
	 connections[i].host);
}

/*
 * sendto_all_linkedbots()
 * 
 * inputs	- command to relay as input
 * output	- NONE
 * side effects	-
 */

void sendto_all_linkedbots(char *buffer)
{
  int i;
#ifdef DEBUGMODE
  placed;
#endif

  for( i = 1; i< maxconns; i++)
    {
      if(connections[i].socket != INVALID)
	{
	  if(connections[i].type & TYPE_TCM)
	    {
	      /*
	       * Don't send something back to tcm it originated from
	       */

	      if ( i != incoming_connnum )
		{
		  prnt(connections[i].socket,buffer);
		}
	    }
	}
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
  snprintf(buff, sizeof(buff),
	   "DEBUG Wrote %s\nFunction History:\n", ctime(&now));
  write(x, buff, strlen(buff));
  for(a=0;a<15;++a)
    {
      snprintf(buff, sizeof(buff), " %s/%d\n", placef[a], placel[a]);
      write(x, buff, strlen(buff));
    }
  snprintf(buff, sizeof(buff),
	   "Last function:\t%s/%d\n", placef[15], placel[15]);
  write(x, buff, strlen(buff));
  close(x);
}
#endif

/*
 * oper()
 *
 * inputs	- Nick to oper
 * output	- NONE
 * side effects	- With any luck, we oper this tcm *sigh*
 */

void oper()
{
  toserv("OPER %s %s\n",
	  config_entries.oper_nick_config,
          config_entries.oper_pass_config);
}

/*
 * send_umodes()
 *
 * inputs	- Nick to change umodes for
 * output	- NONE
 * side effects	- Hopefully, set proper umodes for this tcm
 */

static void send_umodes(char *my_nick)
{
  toserv("MODE %s :+bcdfknrswxyzl\n", my_nick );
  toserv("FLAGS +SKILLS CLICONNECTS +CLIDISCONNECTS +NICKCHANGES +LWALLOPS +CONNECTS +SQUITS +OWALLOPS +STATSNOTICES\n");

  if(config_entries.hybrid && (config_entries.hybrid_version >= 6))
    {
      toserv("STATS I\n");
    }
  else if (config_entries.hybrid)
    {
      toserv("STATS E\n");
      toserv("STATS F\n");
    }
}

/*
 * onjoin()
 * 
 * inputs	- nick, channel, as char string pointers	
 * output	- NONE
 * side effects	-
 */

static void onjoin(char *nick,char *channel)
{
  if (*channel == ':') ++channel;      /* 2.8 fix */
  if (!strcmp(mynick,nick))
    {
      strncpy(mychannel,channel,MAX_CHANNEL-1);
      mychannel[MAX_CHANNEL-1] = 0;
      toserv("MODE %s +nt\n",channel);
    }
}

static void onkick(char *nick,char *channel)
{
  if (!strcmp(mynick,nick))
    {
      if(config_entries.defchannel_key[0])
	join(config_entries.defchannel,config_entries.defchannel_key); 
      else
	join(config_entries.defchannel,(char *)NULL);
    }
}

static void onnick(char *old_nick,char *new_nick)
{
  if (*new_nick == ':')
    ++new_nick;      /* 2.8 fix */

  if (!strcmp(old_nick,mynick))
    strcpy(mynick,new_nick);
}

/*
 * onnicktaken
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- 
 */

static void onnicktaken(void)
{
  char randnick[MAX_NICK];

  (void)sprintf(randnick,"%s%1d",config_entries.dfltnick, rand() % 10);

  if (!*mychannel)
    {
      newnick(randnick);
      strcpy(mynick,randnick);
      
      if(config_entries.defchannel_key[0])
	join(config_entries.defchannel,config_entries.defchannel_key); 
      else
	join(config_entries.defchannel,(char *)NULL);
    }
  else if (strncmp(randnick,config_entries.dfltnick,
		   strlen(config_entries.dfltnick)))
    {
      newnick(randnick);
      strcpy(mynick,randnick);
    }
}

/*
 * cannotjoin
 *
 * inputs	- channel
 * output	- none
 * side effects	- 
 */

static void cannotjoin(char *channel)
{
  char newchan[MAX_CHANNEL];
  int i;

  if (!strcmp(channel,config_entries.defchannel))
    (void)sprintf(newchan,"%.78s2",config_entries.defchannel);
  else
    {
      channel += strlen(config_entries.defchannel);
      i = atoi(channel);
      (void)sprintf(newchan,"%.78s%1d",config_entries.defchannel,i+1);
    }

  if(config_entries.defchannel_key[0])
    join(newchan,config_entries.defchannel_key); 
  else
    join(newchan,(char *)NULL);
}

/*
 * msg_mychannel
 *
 * inputs	- format varargs
 * output	- none
 * side effects	-
 */

void msg_mychannel(char *format, ...)
{
  va_list va;
  char message[MAX_BUFF];

  va_start(va,format);

  vsprintf(message, format, va );

  privmsg(mychannel,message);

  va_end(va);
}

