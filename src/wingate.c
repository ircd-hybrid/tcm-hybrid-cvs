/* $Id: wingate.c,v 1.62 2002/06/24 01:23:27 db Exp $ */


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
#include "modules.h"
#include "userlist.h"
#include "parse.h"
#include "logging.h"
#include "stdcmds.h"
#include "tcm_io.h"
#include "actions.h"
#include "hash.h"

#ifdef DEBUGMODE
#include <stdlib.h>   /* needed for atoi() */
#include <errno.h>    /* needed for errno, obviously. */
#endif

#include "bothunt.h"
#include "wingate.h"

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)


#define SOCKS5_CONNECTING	4
#define SOCKS4_CONNECTING	5
#define SOCKS5_SENTVERSION	6
#define SOCKS4_SENTCONNECT	7
#define SQUID_CONNECTING	8
#define SQUID_READING		9

#ifdef DETECT_WINGATE
int act_wingate;
static void report_open_wingate(struct connection *connection_p);
static void wingate_start_test(struct user_entry *info);
static void read_wingate(struct connection *connection_p);
static int n_open_wingate_fds=0;
#endif

#ifdef DETECT_SOCKS
int act_socks;
static void report_open_socks(struct connection *connection_p);
static void socks_start_test(struct user_entry *info_p, int socksversion);

/* XXX */
#if notyet
static void read_socks(struct connection *connection_p);
#endif

static int n_open_socks_fds=0;
#endif

#ifdef DETECT_SQUID
int act_squid;
static void report_open_squid(struct connection *connection_p);
static void squid_start_test(struct user_entry *info_p, int port);
static void read_squid(struct connection *connection_p);
static int n_open_squid_fds=0;
#endif


#ifdef DEBUGMODE
void m_proxy(struct connection *connection_p, int argc, char *argv[])
{
  if (argc <= 2)
  {
#ifdef DETECT_SQUID
    send_to_connection(connection_p,
		       "Usage: %s <type> <host> [port]", argv[0]);
#else
    send_to_connection(connection_p,
		       "Usage: %s <type> <host>", argv[0]);
#endif
    return;
  }
#ifdef DETECT_WINGATE
  if (strcasecmp(argv[1], "wingate") == 0)
    wingate_bindsocket("test", "user", argv[2]);
#endif
#ifdef DETECT_SOCKS
  if (strcasecmp(argv[1], "socks") == 0)
    socks_bindsocket("test", "user", argv[2], 5);
#endif
#ifdef DETECT_SQUID
  if (argc != 4)
  {
    send_to_connection(connection_p, "Usage: %s squid <host> [port]",
		       argv[0]);
    return;
  }
  if (strcasecmp(argv[1], "squid") == 0)
  {
    squid_bindsocket("test", "user", argv[2], atoi(argv[3]));
  }
#endif
}

struct dcc_command proxy_msgtab = {
 "proxy", NULL, {m_unregistered, m_not_admin, m_proxy}
};
#endif /* DEBUGMODE */

#ifdef DETECT_WINGATE
/*
 * wingate_start_test()
 *
 * inputs	-
 * output	-
 * side effects	- Sets up a socket and connects to the given host
 */
static void
wingate_start_test(struct user_entry *info_p)
{
  struct connection *found_p;
  struct sockaddr_in socketname;

  if (n_open_wingate_fds >= MAXWINGATE)
    return;

  if ((found_p = find_free_connection()) == NULL)
    return;

  n_open_wingate_fds++;

  strlcpy(found_p->pusername, info_p->username, MAX_USER);
  strlcpy(found_p->host, info_p->host, MAX_HOST);
  strlcpy(found_p->nick, info_p->nick, MAX_NICK);
  strlcpy(found_p->ip, info_p->ip_host, MAX_IP);
  found_p->io_read_function = read_wingate;
  found_p->io_write_function = NULL;
  found_p->io_close_function = NULL;

  if (inet_aton(info_p->ip_host, &socketname.sin_addr)) 
    {
      found_p->socket = connect_to_given_ip_port(&socketname, 23);
    }
  else
    {
      close_connection(found_p);
    }
}
#endif

#ifdef DETECT_SOCKS
/*
 * socks_start_test()
 *
 * inputs	-
 * output	-
 * side effects	- Sets up a socket and connects to the given host
 */
static void
socks_start_test(struct user_entry *info_p, int socksversion)
{
  struct connection *found_p;
  struct sockaddr_in socketname;

  /* XXX disable until done */
return;

  if (n_open_socks_fds >= MAXSOCKS)
    return;

  if ((found_p = find_free_connection()) == NULL)
    return;

  n_open_socks_fds++;

  if (socksversion == 4)
    found_p->curr_state = SOCKS4_CONNECTING;
  else if(socksversion == 5)
    found_p->curr_state = SOCKS5_CONNECTING;
  else
    return;

  strlcpy(found_p->username, info_p->username, MAX_USER);
  strlcpy(found_p->host, info_p->host, MAX_HOST);
  strlcpy(found_p->nick, info_p->nick, MAX_NICK);
  strlcpy(found_p->ip, info_p->ip_host, MAX_IP);
  found_p->io_read_function = NULL;
  found_p->io_write_function = NULL;
  found_p->io_close_function = NULL;
  found_p->socket = connect_to_given_ip_port(&socketname, 23);
}
#endif

#ifdef DETECT_SQUID
/*
 * squid_start_test()
 *
 * inputs	-
 * output	-
 * side effects	- Sets up a socket and connects to the given host
 */
static void
squid_start_test(struct user_entry *info_p, int port)
{
  struct connect *found_p;
  struct sockaddr_in socketname;

  if (n_open_squid_fds >= MAXSQUID)
    return;

  if ((found_p = find_free_connection_slot()) == NULL)
    return;

  n_open_squid_fds++;

  found_p->curr_state = SQUID_CONNECTING;
  strlcpy(found_p->username, info_p->username, MAX_USER);
  strlcpy(found_p->host, info_p->host, MAX_HOST);
  strlcpy(found_p->nick, info_p->nick, MAX_NICK);
  strlcpy(found_p->ip, info_p->ip_host, MAX_IP);
  found_p->io_read_function = read_squid;
  found_p->io_write_function = NULL; 
  found_p->io_close_function = NULL;
  if (inet_aton(info_p->ip_host, &socketname.sin_addr)) 
    {
      found_p->socket =	connect_to_given_ip_port(&socketname, port);
    }
  else
    {
      close_connection(found_p);
    }
}
#endif


#ifdef DETECT_WINGATE
static void
read_wingate(struct connection *connection_p)
{
  int open_wingate = NO;
  struct stat buf;
  char *p;

  if (fstat(connection_p->socket, &buf) < 0)
    {
      close_connection(connection_p);
      return;
    }
  
  if ((p = strchr(connection_p->buffer,'W')))
    {
      if (strncasecmp(p,"Wingate>", 8) == 0)
	open_wingate = YES;
    }
  else if ((p = strchr(connection_p->buffer,'T')))
    {
      if (strncasecmp(p, "Too many connected users - try again later",42) == 0)
	open_wingate = YES;
    }
  /*
   * the code used to only close the socket when a host was
   * identified as a Wingate.  this is, of course, wrong.
   * -bill.
   */
  if (open_wingate)
    report_open_wingate(connection_p);

  close_connection(connection_p);
  if (n_open_wingate_fds > 0)
    n_open_wingate_fds--;
}
#endif

#ifdef DETECT_SQUID
static void
read_squid(struct connection *connection_p)
{
  struct stat buf;

  if (connection_p->curr_state != SQUID_READING)
    {
      if (fstat(connection_p->socket, &buf) < 0)
	{
	  close_connection(connection_p);
	  if (n_open_squid_fds > 0)
	    n_open_squid_fds--;
	}
      else
	{
	  send_to_connection(connection_p,
			     "CONNECT %s:%d HTTP/1.0\r\n\r\n",
			     SOCKS_CHECKIP, SOCKS_CHECKPORT);
	  connection_p->curr_state = SQUID_READING;
	}
      return;
    }

  if (strstr(connection_p->buffer, SQUID_STRING) != NULL)
    {
      report_open_squid(connection_p);
    }
  if (n_open_squid_fds > 0)
    n_open_squid_fds--;
  close_connection(connection_p);
}
#endif

/* ZZZ XXX */
#if notyet
#ifdef DETECT_SOCKS

static void
read_socks(struct connection *connection_p)
{
  unsigned char tmp[SMALL_BUFF];

  switch (connection_p->curr_state)
    {
    case SOCKS5_CONNECTING:
      tmp[0] = 5; /* socks version */
      tmp[1] = 1; /* Number of supported auth methods */
      tmp[2] = 0; /* Auth method 0 (no auth) */
      tmp[3] = 0; /* EOF */
      if (write(connection_p->socket, tmp, 4) != 4)
	{
	  close_connection(connection_p);
	  break;
	} 
      connection_p->curr_state = SOCKS5_SENTVERSION;
      break;

    case SOCKS5_SENTVERSION:
      if (connection_p->buffer[0] != '\0')
	{
	  report_open_socks(connection_p);
	}
      else
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "DEBUG: Socks 5 server at %s rejects login\n",
		      connection_p->host);
	    }
	}
      close_connection(connection_p);
      break;

    case SOCKS4_CONNECTING:
      tmp[0] = 4; /* socks v4 */
      tmp[1] = 1; /* connect */

      *((unsigned short *) (tmp+2)) =
	htons(SOCKS_CHECKPORT); /* Connect to port */

      *((unsigned int *) (tmp+4)) = 
	inet_addr(SOCKS_CHECKIP); /* Connect to ip */

      strcpy(tmp+8, "tcm"); /* Dummy username */
      if (write(socks[i].socket, tmp, 12)!=12)
	{
	  close(socks[i].socket);
	  break;
	} 
      if(config_entries.debug && outfile)
	{
	  fprintf(outfile,
		  "DEBUG: Sent Socks 4 CONNECT to %s\n",
		  socks[i].host);
	}
      connections[i].state=SOCKS4_SENTCONNECT;
      break;

    case SOCKS4_SENTCONNECT:
      memset(tmp, 0xCC, sizeof(tmp));
      close(connection_p);
      break;

      if (tmp[1] != 90)
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "DEBUG: Socks 4 server at %s denies connect (0x%02hhx)\n",
		      connection_p->host, tmp[1]);
	    }
	  close_connection(connection_p);
	  break;
	}
      report_open_socks(connection_p);
      close(connection_p);
      break;
    default:
      break;
    }
}
#endif	/* #ifdef SOCKS */
#endif	/* #if notyet */

void
user_signon(struct user_entry *info_p)
{
  if (wingate_class(info_p->class))
    {
#ifdef DETECT_WINGATE
      wingate_start_test(info_p);
#endif
#ifdef DETECT_SOCKS
      socks_start_test(info_p, 4);
      socks_start_test(info_p, 5);
#endif
#ifdef DETECT_SQUID
      squid_start_test(info_p, 80);
      squid_start_test(info_p, 1080);
      squid_start_test(info_p, 8080);
      squid_start_test(info_p, 3128);
#endif
    }
}


/* XXX */
void
_reload_wingate(int connnum, int argc, char *argv[])
{
#if 0
  int cnt;
#endif
}

#ifdef DETECT_WINGATE
static void report_open_wingate(struct connection *connection_p)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "Found wingate open\n");

  handle_action(act_wingate,
		connection_p->nick, connection_p->username,
		connection_p->host, connection_p->ip, 0);
  tcm_log(L_NORM, "Open Wingate %s!%s@%s",
	  connection_p->nick, connection_p->username, connection_p->host);
}
#endif

#ifdef DETECT_SQUID
static
void report_open_squid(struct connection *connection_p)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open squid proxy at %s\n",
	    connection_p->host);

  handle_action(act_squid, connection_p->nick, connection_p->username,
		connection_p->host, connection_p->ip, 0);
  tcm_log(L_NORM, "Open squid proxy %s", connection_p->host);
}
#endif

#ifdef DETECT_SOCKS
static
void report_open_socks(struct connection *connection_p)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open socks proxy at %s\n", 
	    connection_p->host);

  handle_action(act_socks, connection_p->nick, connection_p->username,
		connection_p->host, connection_p->ip, 0);
  tcm_log(L_NORM, "Open socks proxy %s", connection_p->host);
}
#endif

void init_wingates(void)
{
#ifdef DEBUGMODE
  add_dcc_handler(&proxy_msgtab);
#endif
#ifdef DETECT_WINGATE
  init_one_action(&act_wingate, "wingate", HS_WINGATE, REASON_WINGATE);
#endif
#ifdef DETECT_SOCKS
  init_one_action(&act_socks, "socks", HS_SOCKS, REASON_SOCKS);
#endif
#ifdef DETECT_SQUID
  init_one_action(&act_squid, "squid", HS_SQUID, REASON_SQUID);
#endif
}

#endif

