/* $Id: wingate.c,v 1.32 2002/05/24 20:52:44 leeh Exp $ */


#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "config.h"
#include "tcm.h"
#include "commands.h"
#include "modules.h"
#include "userlist.h"
#include "logging.h"
#include "stdcmds.h"
#include "tcm_io.h"
#ifdef DEBUGMODE
#include <stdlib.h>   /* needed for atoi() */
#include <errno.h>    /* needed for errno, obviously. */
#include "serverif.h" /* need connections[] struct for m_proxy() */
#endif

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)

/* Maximum pending connects for wingates */
#define MAXWINGATE 200

/* Maximum pending connects for socks */
#define MAXSOCKS 400 

/* Maximum pending connects for squid */
#define MAXSQUID 400

#define WINGATE_CONNECTING 1
#define WINGATE_READING 2
#define WINGATE_READ 3
#define SOCKS5_CONNECTING 4
#define SOCKS4_CONNECTING 5
#define SOCKS5_SENTVERSION 6
#define SOCKS4_SENTCONNECT 7
#define SQUID_CONNECTING 8
#define SQUID_READING 9

struct wingates {
  char user[MAX_USER];
  char host[MAX_HOST];
  char nick[MAX_NICK+2];        /* allow + 2 for incoming bot names */
  int  socket;
  int  state;
  time_t connect_time;
  struct sockaddr_in socketname;
};

char wingate_class_list[MAXWINGATE][100];
int  wingate_class_list_index;

#ifdef DETECT_WINGATE
int act_wingate;
static void report_open_wingate(int i);
struct wingates wingate[MAXWINGATE];
int wingate_bindsocket(char *nick, char *user, char *host);
#endif

#ifdef DETECT_SOCKS
int act_socks;
static void report_open_socks(int i);
struct wingates socks[MAXSOCKS];
int socks_bindsocket(char *nick, char *user, char *host, int socksversion);
#endif

#ifdef DETECT_SQUID
int act_squid;
static void report_open_squid(int i);
struct wingates squid[MAXSQUID];
int squid_bindsocket(char *nick, char *user, char *host, int port);
#endif

int wingate_class_list_index;

#ifdef DEBUGMODE
void m_proxy(int connnum, int argc, char *argv[])
{
  if (argc <= 2)
  {
#ifdef DETECT_SQUID
    print_to_socket(connections[connnum].socket, "Usage: %s <type> <host> [port]\n",
                    argv[0]);
#else
    print_to_socket(connections[connnum].socket, "Usage: %s <type> <host>\n", argv[0]);
#endif
    return;
  }
#ifdef DETECT_WINGATE
  if (!strcasecmp(argv[1], "wingate"))
    wingate_bindsocket("test", "user", argv[2]);
#endif
#ifdef DETECT_SOCKS
  if (!strcasecmp(argv[1], "socks"))
    socks_bindsocket("test", "user", argv[2], 5);
#endif
#ifdef DETECT_SQUID
  if (argc != 4)
  {
    print_to_socket(connections[connnum].socket, "Usage: %s squid <host> [port]\n",
                    argv[0]);
    return;
  }
  if (!strcasecmp(argv[1], "squid"))
  {
    squid_bindsocket("test", "user", argv[2], atoi(argv[3]));
  }
#endif
}

#ifdef IRCD_HYBRID
/* bleh. */
#else
struct TcmMessage proxy_msgtab = {
 ".proxy", 0, 0,
 {m_unregistered, m_not_admin, m_proxy}
};
#endif
#endif /* DEBUGMODE */

void _scontinuous(int connnum, int argc, char *argv[]);
void _continuous(int connnum, int argc, char *argv[]);
void _user_signon(int connnum, int argc, char *argv[]);
void _reload_wingate(int connnum, int argc, char *argv[]);
void _config(int connnum, int argc, char * argv[]);

#ifdef DETECT_WINGATE
/*
** wingate_bindsocket()
**   Sets up a socket and connects to the given host
*/
int
wingate_bindsocket(char *nick,char *user,char *host)
{
  int plug;
  int result;
  struct hostent *remote_host;
  int flags;
  int optval;
  int i;
  int found_slot = INVALID;

  for(i=0;i<MAXWINGATE;i++)
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

  if (!(remote_host = (struct hostent *)gethostbyname (host)))
    {
      (void)close(plug);
      wingate[found_slot].socket = INVALID;
      return (INVALID);
    }
  (void) memcpy ((void *) &wingate[found_slot].socketname.sin_addr,
                (const void *) remote_host->h_addr,
                (int) remote_host->h_length);

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
int
socks_bindsocket(char *nick,char *user,char *host, int socksversion)
{
  int plug;
  int result;
  struct hostent *remote_host;
  int flags;
  int optval;
  int i;
  int found_slot = INVALID;
  if ((socksversion != 4) && (socksversion != 5))
    return INVALID;

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
  if (socksversion == 4)
    socks[found_slot].state = SOCKS4_CONNECTING;
  else
    socks[found_slot].state = SOCKS5_CONNECTING;
  strncpy(socks[found_slot].user,user,MAX_USER-1);
  strncpy(socks[found_slot].host,host,MAX_HOST-1);
  strncpy(socks[found_slot].nick,nick,MAX_NICK-1);
  (void)memset(&socks[found_slot].socketname, 0, sizeof(struct sockaddr_in));

  (void)setsockopt(plug,SOL_SOCKET,SO_REUSEADDR,(char *)&optval,
                   sizeof(optval));

  socks[found_slot].socketname.sin_family = AF_INET;
  socks[found_slot].socketname.sin_port = htons (1080);

  if (!(remote_host = (struct hostent *)gethostbyname (host)))
    {
      (void)close(plug);
      socks[found_slot].socket = INVALID;
      return (INVALID);
    }
  (void) memcpy ((void *) &socks[found_slot].socketname.sin_addr,
                (const void *) remote_host->h_addr,
                (size_t) remote_host->h_length);

  /* connect socket */

  result = connect(plug, (struct sockaddr *) &socks[found_slot].socketname,
                   sizeof(struct sockaddr_in));
  return (plug);
}
#endif

#ifdef DETECT_SQUID
/*
** squit_bindsocket()
**   Sets up a socket and connects to the given host
*/
int
squid_bindsocket(char *nick, char *user, char *host, int port)
{
  int plug;
  int result;
  struct hostent *remote_host;
  int flags;
  int optval;
  int i;
  int found_slot = INVALID;

  for(i=0;i<MAXWINGATE;i++)
    {
      if(squid[i].socket == INVALID)
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
              "DEBUG: squid_bindsocket() plug = %d set non blocking %d\n",
              plug, result);
    }

  squid[found_slot].socket = plug;
  squid[found_slot].state = SQUID_CONNECTING;
  strncpy(squid[found_slot].user,user,MAX_USER-1);
  strncpy(squid[found_slot].host,host,MAX_HOST-1);
  strncpy(squid[found_slot].nick,nick,MAX_NICK-1);
  (void)memset(&squid[found_slot].socketname, 0, sizeof(struct sockaddr_in));

  (void)setsockopt(plug,SOL_SOCKET,SO_REUSEADDR,(char *)&optval,
                   sizeof(optval));

  squid[found_slot].socketname.sin_family = AF_INET;
  squid[found_slot].socketname.sin_port = htons (port);

  if (!(remote_host = (struct hostent *)gethostbyname (host)))
    {
      (void)close(plug);
      squid[found_slot].socket = INVALID;
      return (INVALID);
    }
  (void) memcpy ((void *) &squid[found_slot].socketname.sin_addr,
                (const void *) remote_host->h_addr,
                (int) remote_host->h_length);

  /* connect socket */

  result = connect(plug, (struct sockaddr *) &squid[found_slot].socketname,
                   sizeof(struct sockaddr_in));
  return (plug);
}
#endif

void
_scontinuous(int connnum, int argc, char *argv[])
{
  int i;

#ifdef DETECT_WINGATE
  for (i=0; i<MAXWINGATE;i++)
    {
      char buffer[256], *p;
      int nread;

      if (wingate[i].socket != INVALID)
        {
          if (FD_ISSET(wingate[i].socket, &writefds))
            {
              struct stat buf;

              if (fstat(wingate[i].socket,&buf) < 0)
                {
                  (void)close(wingate[i].socket);
                  wingate[i].state = 0;
                  wingate[i].socket = INVALID;
                }
              else
                {
                  wingate[i].state = WINGATE_READING;
                  wingate[i].connect_time = current_time;
                }
            }
        }

      if (wingate[i].socket != INVALID)
        {
          int open_wingate = NO;

          if (FD_ISSET(wingate[i].socket, &writefds) || wingate[i].state == WINGATE_READING)
            {
              nread = read(wingate[i].socket,buffer,256);
              if (nread > 0)
                {
                  buffer[nread] = '\0';
                  if ((p = (char *)strchr(buffer,'W')))
                    {
                      if (strncasecmp(p,"Wingate>", 8) == 0)
                        open_wingate = YES;
                    }
                  else if( (p = (char *)strchr(buffer,'T')) )
                    {
                      if (!strncasecmp(p, "Too many connected users - try again later",42))
                        open_wingate = YES;
                    }
                  /*
                   * the code used to only close the socket when a host was
                   * identified as a Wingate.  this is, of course, wrong.
                   * -bill.
                   */
                  if (open_wingate)
                    report_open_wingate(i);

                  (void)close(wingate[i].socket);
                  wingate[i].socket = INVALID;
                  wingate[i].state = 0;
                }
            }
        }
    }
#endif
#ifdef DETECT_SOCKS
  for (i=0; i<MAXSOCKS;i++)
    {
      unsigned char tmp[200];
      int n;

      if (socks[i].socket != INVALID)
        {
          if (FD_ISSET(socks[i].socket, &writefds) || FD_ISSET(socks[i].socket, &readfds)) 
            {
	      switch (socks[i].state) {
	      case SOCKS5_CONNECTING:
		tmp[0] = 5; /* socks version */
		tmp[1] = 1; /* Number of supported auth methods */
		tmp[2] = 0; /* Auth method 0 (no auth) */
		tmp[3] = 0; /* EOF */
		if (write(socks[i].socket, tmp, 4)!=4) {
		  close(socks[i].socket);
		  socks_bindsocket(socks[i].nick, socks[i].user, socks[i].host, 4);
		  socks[i].state = 0;
		  socks[i].socket = INVALID;
		  break;
		} 
		socks[i].state = SOCKS5_SENTVERSION;
		break;
	      case SOCKS5_SENTVERSION:
		memset(tmp, 0, sizeof(tmp));
		n = read(socks[i].socket, tmp, sizeof(tmp));
		if ((n>=2) && (tmp[1]==0)) {
		  /* Server accepts unauthed connections */
		  report_open_socks(i);
		  close(socks[i].socket);
		  socks[i].state = 0;
		  socks[i].socket = INVALID;
		  break;
		}
		if(config_entries.debug && outfile)
		  {
		    fprintf(outfile,
			    "DEBUG: _scontinous: Socks 5 server at %s rejects login\n",
			    socks[i].host);
		  }

		close(socks[i].socket);
		socks_bindsocket(socks[i].nick, socks[i].user, socks[i].host, 4);
		socks[i].state = 0;
		socks[i].socket = INVALID;
		break;
	      case SOCKS4_CONNECTING:
		tmp[0] = 4; /* socks v4 */
		tmp[1] = 1; /* connect */
		*((unsigned short *) (tmp+2)) = htons(SOCKS_CHECKPORT); /* Connect to port */
		*((unsigned int *) (tmp+4)) = inet_addr(SOCKS_CHECKIP); /* Connect to ip */
		strcpy(tmp+8, "tcm"); /* Dummy username */
		if (write(socks[i].socket, tmp, 12)!=12) {
		  close(socks[i].socket);
		  socks[i].state = 0;
		  socks[i].socket = INVALID;
		  break;
		} 
		if(config_entries.debug && outfile)
		  {
		    fprintf(outfile,
			    "DEBUG: _scontinous: Sent Socks 4 CONNECT to %s\n",
			    socks[i].host);
		  }
		socks[i].state=SOCKS4_SENTCONNECT;
		break;
	      case SOCKS4_SENTCONNECT:
		memset(tmp, 0xCC, sizeof(tmp));
		n = read(socks[i].socket, tmp, sizeof(tmp));
		if (n<=0) {
		  if(config_entries.debug && outfile)
		  {
		    fprintf(outfile,
			    "DEBUG: _scontinous: Socks 4 at %s closed connection\n",
			    socks[i].host);
		  }
		  close(socks[i].socket);
		  socks[i].state = 0;
		  socks[i].socket = INVALID;
		  break;
		} 
		if (tmp[1] != 90) {
		  if(config_entries.debug && outfile)
		    {
		      fprintf(outfile,
			      "DEBUG: _scontinous: Socks 4 server at %s denies connect (0x%02hhx)\n",
			      socks[i].host, tmp[1]);
		    }
		  close(socks[i].socket);
		  socks[i].state = 0;
		  socks[i].socket = INVALID;
		  break;
		}
		report_open_socks(i);
		close(socks[i].socket);
		socks[i].state = 0;
		socks[i].socket = INVALID;
		break;
	      default:
		break;
	      }
            }
        }
    }
#endif
#ifdef DETECT_SQUID
  for (i=0; i<MAXSQUID; i++)
  {
    if (squid[i].socket != INVALID && FD_ISSET(squid[i].socket, &writefds))
    {
      struct stat buf;

      if (fstat(squid[i].socket, &buf) < 0)
      {
        close(squid[i].socket);
        squid[i].state = 0;
        squid[i].socket = INVALID;
      }
      else
      {
        print_to_socket(squid[i].socket, "CONNECT %s:%d HTTP/1.0\r\n\r\n",
                        SOCKS_CHECKIP, SOCKS_CHECKPORT);
        squid[i].state = SQUID_READING;
        squid[i].connect_time = current_time;
      }
    }

    if (squid[i].socket != INVALID && FD_ISSET(squid[i].socket, &readfds))
    {
      char buffer[256];
      int nread;

      if ((nread = read(squid[i].socket, buffer, sizeof(buffer)-1)) > 0)
      {
        if (strstr(buffer, SQUID_STRING) != NULL)
        {
          report_open_squid(i);
          continue;
        }
      }
      else
      {
        close(squid[i].socket);
        squid[i].state = 0;
        squid[i].socket = INVALID;
      }
    }
  }
#endif
}

void
_continuous(int connnum, int argc, char *argv[])
{
  int i;

  FD_ZERO (&writefds);
#ifdef DETECT_WINGATE
  for (i=0; i<MAXWINGATE;i++)
    {
      if (wingate[i].socket != INVALID)
        {
          if (wingate[i].state == WINGATE_CONNECTING)
            FD_SET(wingate[i].socket,&writefds);
          else if( (wingate[i].state == WINGATE_READING))
            {
              if (current_time > (wingate[i].connect_time + 10))
                {
                  (void)close(wingate[i].socket);
                  wingate[i].socket = INVALID;
                  wingate[i].state = 0;
                }
              else if(current_time > (wingate[i].connect_time + 1))
                FD_SET(wingate[i].socket,&readfds);
            }
        }
    }
#endif
#ifdef DETECT_SOCKS
  for (i=0; i<MAXSOCKS;i++) {
    if ((socks[i].socket != INVALID) && ((socks[i].state == SOCKS4_CONNECTING)
        || (socks[i].state == SOCKS5_CONNECTING)))
    {
      FD_SET(socks[i].socket,&writefds);
    }
    else if ((socks[i].socket != INVALID) && 
	     ((socks[i].state >= SOCKS5_SENTVERSION)))
    {
      FD_SET(socks[i].socket,&readfds);
    }
  }
#endif
#ifdef DETECT_SQUID
  for (i=0; i<MAXSQUID;i++)
  {
    if ((squid[i].socket != INVALID) && (squid[i].state == SQUID_CONNECTING))
    {
      FD_SET(squid[i].socket, &writefds);
    }
    else if ((squid[i].socket != INVALID) && (squid[i].state == SQUID_READING))
    {
      if (current_time > (squid[i].connect_time + 10))
      {
        close(squid[i].socket);
        squid[i].socket = INVALID;
        squid[i].state = 0;
      }
      else if (current_time > (squid[i].connect_time + 1))
        FD_SET(squid[i].socket, &readfds);
    }
  }
#endif
}

void
_config(int connnum, int argc, char *argv[])
{
  if ((argc==2) && ((argv[0][0]=='w') || (argv[0][0]=='W')))
  {
    strncpy(wingate_class_list[wingate_class_list_index], argv[1], 
	    sizeof(wingate_class_list[0]));
    wingate_class_list_index++;
  }
}

void
_user_signon(int connnum, int argc, char *argv[])
{
  if (connnum) return; /* in this case, connnum means if it's from TRACE or not */
  if (wingate_class(argv[4]))
    {
#ifdef DETECT_WINGATE
      wingate_bindsocket(argv[0], argv[1], argv[2]);
#endif
#ifdef DETECT_SOCKS
      socks_bindsocket(argv[0], argv[1], argv[2], 5);
#endif
#ifdef DETECT_SQUID
      squid_bindsocket(argv[0], argv[1], argv[2], 80);
      squid_bindsocket(argv[0], argv[1], argv[2], 1080);
      squid_bindsocket(argv[0], argv[1], argv[2], 8080);
      squid_bindsocket(argv[0], argv[1], argv[2], 3128);
#endif
    }
}

void
_reload_wingate(int connnum, int argc, char *argv[])
{
  int cnt;

#ifdef DETECT_WINGATE
  wingate_class_list_index = 0;
  for(cnt = 0; cnt < MAXWINGATE; cnt++)
    {
      if(wingate[cnt].socket != INVALID)
        {
          (void)close(wingate[cnt].socket);
        }
      wingate[cnt].socket = INVALID;
      wingate[cnt].user[0] = '\0';
      wingate[cnt].host[0] = '\0';
      wingate[cnt].state = 0;
      wingate[cnt].nick[0] = '\0';
    }
#endif
#ifdef DETECT_SOCKS
  for(cnt = 0; cnt < MAXSOCKS; cnt++)
    {
      if(socks[cnt].socket != INVALID)
        {
          (void)close(socks[cnt].socket);
        }
      socks[cnt].socket = INVALID;
      socks[cnt].user[0] = '\0';
      socks[cnt].host[0] = '\0';
      socks[cnt].state = 0;
      socks[cnt].nick[0] = '\0';
    }
#endif
#ifdef DETECT_SQUID
  for (cnt = 0; cnt < MAXSQUID; cnt++)
  {
    if (squid[cnt].socket != INVALID)
      close(squid[cnt].socket);
    squid[cnt].socket = INVALID;
    squid[cnt].user[0] = '\0';
    squid[cnt].host[0] = '\0';
    squid[cnt].state = 0;
    squid[cnt].nick[0] = '\0';
  }
#endif
}

/*
 * wingate_class
 *
 * inputs       - class
 * output       - if this class is a wingate class to check
 * side effects - none
 */

int
wingate_class(char *class)
{
  int i;

  for(i=0; (strlen(wingate_class_list[i]) > 0) ;i++)
    {
      if(!strcasecmp(wingate_class_list[i], class))
        {
          return YES;
        }
    }
  return(NO);
}

#ifdef DETECT_WINGATE
static void report_open_wingate(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "Found wingate open\n");
  
  
  handle_action(act_wingate, 0, wingate[i].nick, wingate[i].user, wingate[i].host, inet_ntoa(wingate[i].socketname.sin_addr), 0);
  log("Open Wingate %s!%s@%s\n",
      wingate[i].nick, wingate[i].user, wingate[i].host);
}

#endif

#ifdef DETECT_SOCKS
static
void report_open_socks(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open socks proxy at %s\n", socks[i].host);

  handle_action(act_socks, 0, socks[i].nick, socks[i].user, socks[i].host, inet_ntoa(socks[i].socketname.sin_addr), 0);
  log("Open socks proxy %s\n",socks[i].host);
}
#endif

#ifdef DETECT_SQUID
static
void report_open_squid(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open squid proxy at %s\n", squid[i].host);

  handle_action(act_squid, 0, squid[i].nick, squid[i].user, squid[i].host,
                inet_ntoa(squid[i].socketname.sin_addr), 0);
  log("Open squid proxy %s\n", squid[i].host);
}
#endif

void init_wingates(void)
{
  int i;
#ifdef DEBUGMODE
  mod_add_cmd(&proxy_msgtab);
#endif
  wingate_class_list_index = 0;
#ifdef DETECT_WINGATE
  act_wingate = add_action("wingate");
  set_action_strip(act_wingate, HS_WINGATE);
  set_action_reason(act_wingate, REASON_WINGATE);
  for (i=0;i<MAXWINGATE;++i)
    wingate[i].socket = INVALID;
#endif
#ifdef DETECT_SOCKS
  act_socks = add_action("socks");
  set_action_strip(act_socks, HS_SOCKS);
  set_action_reason(act_socks, REASON_SOCKS);  

  for (i=0;i<MAXSOCKS;++i)
  {
    socks[i].socket = INVALID;
    socks[i].user[0] = '\0';
    socks[i].host[0] = '\0';
    socks[i].state = 0;
    socks[i].nick[0] = '\0';
  }
#endif
#ifdef DETECT_SQUID
  act_squid = add_action("squid");
  set_action_strip(act_squid, HS_SQUID);
  set_action_reason(act_squid, REASON_SQUID);

  for (i=0; i<MAXSQUID;++i)
  {
    squid[i].socket = INVALID;
    squid[i].user[0] = '\0';
    squid[i].host[0] = '\0';
    squid[i].state = 0;
    squid[i].nick[0] = '\0';
  }
#endif
}

#endif
