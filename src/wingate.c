/* $Id: wingate.c,v 1.41 2002/05/26 15:26:00 db Exp $ */


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
#endif

#include "bothunt.h"
#include "wingate.h"

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)

/* Maximum pending connects for wingates */
#define MAXWINGATE 200

/* Maximum pending connects for socks */
#define MAXSOCKS 400 

/* Maximum pending connects for squid */
#define MAXSQUID 400

#define SOCKS5_CONNECTING	4
#define SOCKS4_CONNECTING	5
#define SOCKS5_SENTVERSION	6
#define SOCKS4_SENTCONNECT	7
#define SQUID_CONNECTING	8
#define SQUID_READING		9

#ifdef DETECT_WINGATE
int act_wingate;
static void report_open_wingate(int i);
static void wingate_start_test(struct plus_c_info *info);
static void read_wingate(int i);
#endif

#ifdef DETECT_SOCKS
int act_socks;
static void report_open_socks(int i);
static void socks_start_test(struct plus_c_info *info_p, int socksversion);

/* XXX */
#if notyet
static void read_socks(int i);
#endif
#endif

#ifdef DETECT_SQUID
int act_squid;
static void report_open_squid(int i);
static void squid_start_test(struct plus_c_info *info_p, int port);
static void read_squid(int i);
#endif


#ifdef DEBUGMODE
void m_proxy(int connnum, int argc, char *argv[])
{
  if (argc <= 2)
  {
#ifdef DETECT_SQUID
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <type> <host> [port]",
                    argv[0]);
#else
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <type> <host>", argv[0]);
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
    print_to_socket(connections[connnum].socket,
		    "Usage: %s squid <host> [port]",
                    argv[0]);
    return;
  }
  if (!strcasecmp(argv[1], "squid"))
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
wingate_start_test(struct plus_c_info *info_p)
{
  int found_slot;
  struct sockaddr_in socketname;

  found_slot = find_free_connection_slot(NULL);
  if (found_slot < 0)
    return;

  strncpy(connections[found_slot].user,info_p->user,MAX_USER-1);
  strncpy(connections[found_slot].host,info_p->host,MAX_HOST-1);
  strncpy(connections[found_slot].nick,info_p->nick,MAX_NICK-1);
  strncpy(connections[found_slot].ip,info_p->ip,MAX_IP-1);
  connections[found_slot].io_read_function = NULL;
  connections[found_slot].io_write_function = NULL;
  if (inet_aton(info_p->ip, &socketname.sin_addr)) 
    {
      connections[found_slot].socket =
	connect_to_given_ip_port(&socketname, 23);
    }
  else
    {
      close_connection(found_slot);
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
socks_start_test(struct plus_c_info *info_p, int socksversion)
{
  int found_slot;
  struct sockaddr_in socketname;

  found_slot = find_free_connection_slot(NULL);
  if (found_slot < 0)
    return;

  if (socksversion == 4)
    connections[found_slot].user_state = SOCKS4_CONNECTING;
  else if(socksversion == 5)
    connections[found_slot].user_state = SOCKS5_CONNECTING;
  else
    return;

  strncpy(connections[found_slot].user, info_p->user, MAX_USER-1);
  strncpy(connections[found_slot].host, info_p->host, MAX_HOST-1);
  strncpy(connections[found_slot].nick, info_p->nick,MAX_NICK-1);
  strncpy(connections[found_slot].ip, info_p->ip,MAX_IP-1);
  connections[found_slot].io_read_function = NULL;
  connections[found_slot].io_write_function = NULL;

  connections[found_slot].socket = connect_to_given_ip_port(&socketname, 23);
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
squid_start_test(struct plus_c_info *info_p, int port)
{
  int found_slot;
  struct sockaddr_in socketname;

  found_slot = find_free_connection_slot(NULL);
  if (found_slot < 0)
    return;

  connections[found_slot].user_state = SQUID_CONNECTING;
  strncpy(connections[found_slot].user, info_p->user, MAX_USER-1);
  strncpy(connections[found_slot].host, info_p->host, MAX_HOST-1);
  strncpy(connections[found_slot].nick, info_p->nick, MAX_NICK-1);
  strncpy(connections[found_slot].ip, info_p->ip, MAX_IP-1);

  connections[found_slot].io_read_function = read_squid;
  connections[found_slot].io_write_function = NULL;
  if (inet_aton(info_p->ip, &socketname.sin_addr)) 
    {
      connections[found_slot].socket =
	connect_to_given_ip_port(&socketname, port);
    }
  else
    {
      close_connection(found_slot);
    }
}
#endif


#ifdef DETECT_WINGATE
static void
read_wingate(int i)
{
  int open_wingate = NO;
  struct stat buf;
  char *p;

  if (fstat(connections[i].socket,&buf) < 0)
    {
      close_connection(i);
      return;
    }
  
  if ((p = strchr(connections[i].buffer,'W')))
    {
      if (strncasecmp(p,"Wingate>", 8) == 0)
	open_wingate = YES;
    }
  else if ((p = strchr(connections[i].buffer,'T')))
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

  close_connection(i);
  connections[i].user_state = 0;
}
#endif

#ifdef DETECT_SQUID
static void
read_squid(int i)
{
  struct stat buf;

  if (connections[i].user_state != SQUID_READING)
    {
      if (fstat(connections[i].socket, &buf) < 0)
	{
	  close_connection(i);
	}
      else
	{
	  print_to_socket(connections[i].socket,
			  "CONNECT %s:%d HTTP/1.0\r\n\r\n",
			  SOCKS_CHECKIP, SOCKS_CHECKPORT);
	  connections[i].user_state = SQUID_READING;
	}
      return;
    }

  if (strstr(connections[i].buffer, SQUID_STRING) != NULL)
    {
      report_open_squid(i);
    }
  close_connection(i);
}
#endif

/* ZZZ XXX */
#if notyet
#ifdef DETECT_SOCKS

static void
read_socks(int i)
{
  unsigned char tmp[SMALL_BUFF];

  switch (connections[i].user_state)
    {
    case SOCKS5_CONNECTING:
      tmp[0] = 5; /* socks version */
      tmp[1] = 1; /* Number of supported auth methods */
      tmp[2] = 0; /* Auth method 0 (no auth) */
      tmp[3] = 0; /* EOF */
      if (write(connections[i].socket, tmp, 4) != 4)
	{
	  close_connection(i);
	  break;
	} 
      connections[i].user_state = SOCKS5_SENTVERSION;
      break;

    case SOCKS5_SENTVERSION:
      if (connections[i].buffer[0] != '\0')
	{
	  report_open_socks(i);
	}
      else
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "DEBUG: Socks 5 server at %s rejects login\n",
		      connections[i].host);
	    }
	}
      close_connection(i);
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
      close(connections[i].socket);
      break;

      if (tmp[1] != 90)
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "DEBUG: Socks 4 server at %s denies connect (0x%02hhx)\n",
		      connections[i].host, tmp[1]);
	    }
	  close_connection(i);
	  break;
	}
      report_open_socks(i);
      close(connections[i].socket);
      break;
    default:
      break;
    }
}
#endif	/* #ifdef SOCKS */
#endif	/* #if notyet */

void
_config(int connnum, int argc, char *argv[])
{
#if notyet
  if ((argc==2) && ((argv[0][0]=='w') || (argv[0][0]=='W')))
  {
    strncpy(wingate_class_list[wingate_class_list_index], argv[1], 
	    sizeof(wingate_class_list[0]));
    wingate_class_list_index++;
  }
#endif
}

void
user_signon(struct plus_c_info *info_p)
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
static void report_open_wingate(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "Found wingate open\n");

  handle_action(act_wingate, 0,
		connections[i].nick, connections[i].user,
		connections[i].host, connections[i].ip, 0);
  log("Open Wingate %s!%s@%s\n",
      connections[i].nick, connections[i].user, connections[i].host);
}
#endif

#ifdef DETECT_SQUID
static
void report_open_squid(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open squid proxy at %s\n",
	    connections[i].host);

  handle_action(act_squid, 0, connections[i].nick, connections[i].user,
		connections[i].host, connections[i].ip, 0);
  log("Open squid proxy %s\n", connections[i].host);
}
#endif

#ifdef DETECT_SOCKS
static
void report_open_socks(int i)
{
  if (config_entries.debug && outfile)
    fprintf(outfile, "DEBUG: Found open socks proxy at %s\n", 
	    connections[i].host);

  handle_action(act_socks, 0, connections[i].nick, connections[i].user,
		connections[i].host, connections[i].ip, 0);
  log("Open socks proxy %s\n", connections[i].host);
}
#endif

void init_wingates(void)
{
#ifdef DEBUGMODE
  add_dcc_handler(&proxy_msgtab);
#endif
/* XXX */
#if notyet
  wingate_class_list_index = 0;
#endif
#ifdef DETECT_WINGATE
  act_wingate = add_action("wingate");
  set_action_strip(act_wingate, HS_WINGATE);
  set_action_reason(act_wingate, REASON_WINGATE);
#endif
#ifdef DETECT_SOCKS
  act_socks = add_action("socks");
  set_action_strip(act_socks, HS_SOCKS);
  set_action_reason(act_socks, REASON_SOCKS);  
#endif
#ifdef DETECT_SQUID
  act_squid = add_action("squid");
  set_action_strip(act_squid, HS_SQUID);
  set_action_reason(act_squid, REASON_SQUID);
#endif
}

#endif

