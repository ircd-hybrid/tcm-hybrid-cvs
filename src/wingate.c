/* $Id: wingate.c,v 1.22 2002/04/02 23:24:26 bill Exp $ */


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

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
#undef REPORT_WINGATES_TO_CHANNEL
#undef REPORT_SOCKS_TO_CHANNEL

#define REASON_WINGATE "Open wingate"
#define REASON_SOCKS   "Open SOCKS"

/* Maximum pending connects for wingates */
#define MAXWINGATES 200

/* Maximum pending connects for socks */
#define MAXSOCKS 400 

#define WINGATE_CONNECTING 1
#define WINGATE_READING 2
#define WINGATE_READ 3
#define SOCKS5_CONNECTING 4
#define SOCKS4_CONNECTING 5
#define SOCKS5_SENTVERSION 6
#define SOCKS4_SENTCONNECT 7

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
struct wingates {
  char user[MAX_USER];
  char host[MAX_HOST];
  char nick[MAX_NICK+2];        /* allow + 2 for incoming bot names */
  int  socket;
  int  state;
  time_t connect_time;
  struct sockaddr_in socketname;
};
#endif

char *_version="20012009";

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
char wingate_class_list[MAXWINGATES][100];
int  wingate_class_list_index;
extern fd_set writefds;
extern fd_set readfds;
#endif

#ifdef DETECT_WINGATE
#define R_WINGATE 0x040
static void report_open_wingate(int i);
struct wingates wingate[MAXWINGATES];
#endif

#ifdef DETECT_SOCKS
#define R_SOCKS 0x080
static void report_open_socks(int i);
struct wingates socks[MAXSOCKS];
#endif

int wingate_class_list_index;

extern time_t cur_time;

void _scontinuous(int connnum, int argc, char *argv[]);
void _continuous(int connnum, int argc, char *argv[]);
void _user_signon(int connnum, int argc, char *argv[]);
void _reload_wingate(int connnum, int argc, char *argv[]);
void _config(int connnum, int argc, char * argv[]);
void _modinit();

#ifdef DETECT_WINGATE
int wingate_bindsocket(char *nick,char *user,char *host);
#endif
#ifdef DETECT_SOCKS
int socks_bindsocket(char *nick,char *user,char *host,int socksversion);
#endif

#ifdef DETECT_WINGATE
/*
** wingate_bindsocket()
**   Sets up a socket and connects to the given host
*/
int wingate_bindsocket(char *nick,char *user,char *host)
{
  int plug;
  int result;
  struct hostent *remote_host;
  int flags;
  int optval;
  int i;
  int found_slot = INVALID;

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
int socks_bindsocket(char *nick,char *user,char *host, int socksversion)
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

  if ( !(remote_host = (struct hostent *)gethostbyname (host)) )
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

void _scontinuous(int connnum, int argc, char *argv[])
{
  unsigned char tmp[200];
  int i, n;

#ifdef DETECT_WINGATE
  for (i=0; i<MAXWINGATES;i++)
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
                  wingate[i].connect_time = cur_time;
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
                      if (strncasecmp(p,"Wingate> ",9) == 0)
                        open_wingate = YES;
                    }
                  else if( (p = (char *)strchr(buffer,'T')) )
                    {
                      if (!strncasecmp(p, "Too many connected users - try again later",42))
                        open_wingate = YES;
                    }
                  if (open_wingate)
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

}

void _continuous(int connnum, int argc, char *argv[])
{
  int i;

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
  FD_ZERO (&writefds);
#endif
#ifdef DETECT_WINGATE
  for (i=0; i<MAXWINGATES;i++)
    {
      if (wingate[i].socket != INVALID)
        {
          if (wingate[i].state == WINGATE_CONNECTING)
            FD_SET(wingate[i].socket,&writefds);
          else if( (wingate[i].state == WINGATE_READING))
            {
              if (cur_time > (wingate[i].connect_time + 10))
                {
                  (void)close(wingate[i].socket);
                  wingate[i].socket = INVALID;
                  wingate[i].state = 0;
                }
              else if(cur_time > (wingate[i].connect_time + 1))
                FD_SET(wingate[i].socket,&readfds);
            }
        }
    }
#endif
#ifdef DETECT_SOCKS
  for (i=0; i<MAXSOCKS;i++) {
    if ((socks[i].socket != INVALID) && ((socks[i].state == SOCKS4_CONNECTING) || (socks[i].state == SOCKS5_CONNECTING)))
      FD_SET(socks[i].socket,&writefds);
    else if ((socks[i].socket != INVALID) && 
	     ((socks[i].state >= SOCKS5_SENTVERSION)))
      FD_SET(socks[i].socket,&readfds);
  }
#endif
}
void _config(int connnum, int argc, char *argv[]) {
#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
  if ((argc==2) && ((argv[0][0]=='w') || (argv[0][0]=='W'))) {
    strncpy(wingate_class_list[wingate_class_list_index], argv[1], 
	    sizeof(wingate_class_list[0]));
    wingate_class_list_index++;
  }
#endif
}

void _user_signon(int connnum, int argc, char *argv[])
{
  if (connnum) return; /* in this case, connnum means if it's from TRACE or not */
  if (wingate_class(argv[4]))
    {
#ifdef DETECT_WINGATE
      wingate_bindsocket(argv[0], argv[1], argv[2]);
#endif
#ifdef DETECT_SOCKS
      socks_bindsocket(argv[0], argv[1], argv[2], 5);
      socks_bindsocket(argv[0], argv[1], argv[2], 4);
#endif
    }
}

void _reload_wingate(int connnum, int argc, char *argv[])
{
  int cnt;

#ifdef DETECT_WINGATE
  wingate_class_list_index = 0;
  for(cnt = 0; cnt < MAXWINGATES; cnt++)
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
}

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
/*
 * wingate_class
 *
 * inputs       - class
 * output       - if this class is a wingate class to check
 * side effects - none
 */

int wingate_class(char *class)
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
#endif

#ifdef DETECT_WINGATE
static void report_open_wingate(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "Found wingate open\n");

  suggest_action(get_action_type("wingate"), wingate[i].nick, wingate[i].user, wingate[i].host,
                 NO, NO);
  log("Open Wingate %s!%s@%s\n",
      wingate[i].nick, wingate[i].user, wingate[i].host);
}

#endif

#ifdef DETECT_SOCKS
static void report_open_socks(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open socks proxy at %s\n", socks[i].host);

  suggest_action(get_action_type("socks"), socks[i].nick, socks[i].user, socks[i].host, NO, NO);
  log("Open socks proxy %s\n",socks[i].host);
}
#endif

void _modinit()
{
  int i;
  add_common_function(F_RELOAD, _reload_wingate);
  add_common_function(F_USER_SIGNON, _user_signon);
  add_common_function(F_CONTINUOUS, _continuous);
  add_common_function(F_SCONTINUOUS, _scontinuous);
  add_common_function(F_CONFIG, _config);
  wingate_class_list_index = 0;
#ifdef DETECT_WINGATE
  add_action("wingate", "warn", REASON_WINGATE);
  set_action_type("wingate", R_WINGATE);
  for (i=0;i<MAXWINGATES;++i)
    wingate[i].socket = INVALID;
#endif
#ifdef DETECT_SOCKS
  add_action("socks", "warn", "Open SOCKS");
  set_action_type("socks", R_SOCKS);
  for (i=0;i<MAXWINGATES;++i)
    {
      socks[i].socket = INVALID;
      socks[i].user[0] = '\0';
      socks[i].host[0] = '\0';
      socks[i].state = 0;
      socks[i].nick[0] = '\0';
    }
#endif
}

#endif
