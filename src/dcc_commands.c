/* $Id: dcc_commands.c,v 1.117 2002/05/31 01:54:18 wcampbel Exp $ */

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>

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
#include "event.h"
#include "parse.h"
#include "bothunt.h"
#include "userlist.h"
#include "logging.h"
#include "stdcmds.h"
#include "modules.h"
#include "tcm_io.h"
#include "wild.h"
#include "match.h"
#include "actions.h"
#include "handler.h"
#include "hash.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

static void register_oper(int connnum, char *password, char *who_did_command);
static void list_opers(int sock);
static void list_exemptions(int sock);
static void handle_save(int sock,char *nick);
static int  is_legal_pass(int connect_id,char *password);
static void print_help(int sock,char *text);

static void m_class(int connnum, int argc, char *argv[]);
static void m_classt(int connnum, int argc, char *argv[]);
static void m_killlist(int connnum, int argc, char *argv[]);
static void m_kline(int connnum, int argc, char **argv);
static void m_kill(int connnum, int argc, char *argv[]);
static void m_kaction(int connnum, int argc, char *argv[]);
static void m_register(int connnum, int argc, char *argv[]);
static void m_opers(int connnum, int argc, char *argv[]);
static void m_testline(int connnum, int argc, char *argv[]);
static void m_uptime(int connnum, int argc, char *argv[]);
static void m_exemptions(int connnum, int argc, char *argv[]);
static void m_connections(int connnum, int argc, char *argv[]);
static void m_disconnect(int connnum, int argc, char *argv[]);
static void m_help(int connnum, int argc, char *argv[]);
static void m_motd(int connnum, int argc, char *argv[]);
static void m_save(int connnum, int argc, char *argv[]);
static void m_close(int connnum, int argc, char *argv[]);
static void m_op(int connnum, int argc, char *argv[]);
static void m_cycle(int connnum, int argc, char *argv[]);
static void m_die(int connnum, int argc, char *argv[]);
static void m_restart(int connnum, int argc, char *argv[]);
static void m_info(int connnum, int argc, char *argv[]);
static void m_locops(int connnum, int argc, char *argv[]);
static void m_unkline(int connnum, int argc, char *argv[]);
static void m_dline(int connnum, int argc, char *argv[]);
#ifdef ENABLE_QUOTE
static void m_quote(int connnum, int argc, char *argv[]);
#endif
static void m_mem(int connnum, int argc, char *argv[]);
static void m_nflood(int connnum, int argc, char *argv[]);
static void m_rehash(int connnum, int argc, char *argv[]);
static void m_trace(int connnum, int argc, char *argv[]);
static void m_failures(int connnum, int argc, char *argv[]);
static void m_domains(int connnum, int argc, char *argv[]);
static void m_nfind(int connnum, int argc, char *argv[]);
static void m_list(int connnum, int argc, char *argv[]);
static void m_ulist(int connnum, int argc, char *argv[]);
static void m_hlist(int connnum, int argc, char *argv[]);

void
m_class(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <class name>", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], NO);
}

void
m_classt(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <class name>", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], YES);
}

void
m_killlist(int connnum, int argc, char *argv[])
{
  char reason[MAX_REASON];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc < 4 && (strcasecmp(argv[1], "-r") == 0)))
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: .killlist [-r] <wildcarded/regex userhost> <reason>");
    return;
  }

  if (argc >= 4)
  {
    expand_args(reason, MAX_REASON-1, argc-3, argv+3);
  }
#else
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
         "Usage: %s <wildcarded userhost> <reason>", argv[0]);
    return;
  }

  if (argc >= 3)
  {
    expand_args(reason, sizeof(reason)-1, argc-2, argv+2);
  }
#endif
  else
    snprintf(reason, sizeof(reason), "No reason");

  if(has_umode(connnum, FLAGS_INVS) == 0)
  {
    strncat(reason, " (requested by ", MAX_REASON - strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            MAX_REASON - strlen(reason));
    strncat(reason, ")", MAX_REASON - strlen(reason));
  }

#ifdef HAVE_REGEX_H
  if (strcasecmp(argv[1], "-r") == 0)
  {
    send_to_all(FLAGS_ALL, "*** killlist %s :%s by %s", argv[2],
                reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[2], reason, YES);
  }
  else
#endif
  {
    send_to_all(FLAGS_ALL, "*** killlist %s :%s by %s", argv[1],
                reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[1], reason, NO);
  }
}

void
m_kline(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  int kline_time;

  if (argc < 3)
    print_to_socket(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]> [reason]", argv[0]);
  else
  {
    if ((kline_time = atoi(argv[1])))
    {
      if (argc >= 4)
      {
	expand_args(buff, MAX_BUFF-1, argc-3, argv+3);
      }
      else
        snprintf(buff, sizeof(buff), "No reason");
      do_a_kline(kline_time, argv[2], buff, 
                 connections[connnum].registered_nick);
    }
    else
    {
      if (argc >= 3)
      {
	expand_args(buff, MAX_BUFF-1, argc-2, argv+2);
      }
      do_a_kline(0, argv[1], buff,
		 connections[connnum].registered_nick);
    }
  }
}

void
m_kill(int connnum, int argc, char *argv[])
{
  char reason[MAX_REASON];

  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
         "Usage: %s <nick|user@host> [reason]", argv[0]);
    return;
  }
  else if (argc == 2)
    snprintf(reason, MAX_REASON-1, "No reason");
  else
  {
    expand_args(reason, MAX_REASON-1, argc-2, argv+2);
  }

  send_to_all(FLAGS_VIEW_KLINES, "*** kill %s :%s by %s",
              argv[1], reason, connections[connnum].registered_nick);
  log_kline("KILL", argv[1], 0, connections[connnum].registered_nick, reason);

  if(has_umode(connnum, FLAGS_INVS) == 0)
  {
    strncat(reason, " (requested by ", MAX_REASON - 1 - strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            MAX_REASON - 1 - strlen(reason));
    strncat(reason, ")", MAX_REASON - strlen(reason));
  }

  print_to_server("KILL %s :%s", argv[1], reason);
}

void
m_kaction(int connnum, int argc, char *argv[])
{
  char *userhost;
  char *p;
  int actionid;

  if(argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [time] <[nick]|[user@host]>", argv[0]);
    return;
  }

  /* skip past .k bit */
  actionid = find_action(argv[0]+2);

  if(argc == 2)
  {
    if((p = strchr(argv[1], '@')) != NULL)
    {
      *p++ = '\0';
      userhost = get_method_userhost(actionid, NULL, argv[1], p);
    }
    else
    {
      userhost = get_method_userhost(actionid, argv[1], NULL, NULL);
    }

    print_to_server("KLINE %s :%s", userhost, actions[actionid].reason);
  }
  else
  {
    if((p = strchr(argv[1], '@')) != NULL)
    {
      *p++ = '\0';
      userhost = get_method_userhost(actionid, NULL, argv[2], p);
    }
    else
    {
      userhost = get_method_userhost(actionid, argv[2], NULL, NULL);
    }

    print_to_server("KLINE %s %s :%s", 
		    argv[1], userhost, actions[actionid].reason);
  }
}

void
m_register(int connnum, int argc, char *argv[])
{
  if(has_umode(connnum, FLAGS_OPER))
  {
    print_to_socket(connections[connnum].socket, 
		    "You are already registered.");
    return;
  }

  if (argc != 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <password>", argv[0]);
  else
    register_oper(connnum, argv[1], connections[connnum].nick);
}

void m_opers(int connnum, int argc, char *argv[])
{
  list_opers(connections[connnum].socket);
}

void
m_testline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <mask>", argv[0]);
    return;
  }
  if (strcasecmp(argv[1], testlines.umask) == 0)
  {
    print_to_socket(connections[connnum].socket,
		    "Already pending %s", argv[1]);
    return;
  }
  snprintf(testlines.umask, sizeof(testlines.umask), "%s", argv[1]);
  testlines.index = connnum;
  print_to_server("TESTLINE %s", argv[1]);
}

void
m_uptime(int connnum, int argc, char *argv[])
{
  report_uptime(connections[connnum].socket);
}

void m_exemptions(int connnum, int argc, char *argv[])
{
  list_exemptions(connections[connnum].socket);
}

void
m_connections(int connnum, int argc, char *argv[])
{
  list_connections(connections[connnum].socket);
}

void
m_disconnect(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <nick>", argv[0]);
  else
  {
    int i;

    i = find_user_in_connections(argv[1]);

    if(i >= 0)
    {
      print_to_socket(connnum, "Disconnecting oper %s", connections[i].nick);
      print_to_socket(connections[i].socket, 
		      "You have been disconnected by oper %s",
		      connections[connnum].registered_nick);
      close_connection(i);
    }
  }
}

void
m_help(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s ?", argv[0]);
  else
    print_help(connections[connnum].socket, argv[1]);
}

void
m_motd(int connnum, int argc, char *argv[])
{
  print_motd(connections[connnum].socket);
}

void
m_save(int connnum, int argc, char *argv[])
{
  handle_save(connections[connnum].socket, 
              connections[connnum].registered_nick);
}

void
m_close(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "Closing connection");
  close_connection(connnum);
}

void
m_op(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <nick>", argv[0]);
  else
    op(config_entries.defchannel, argv[1]);
}

void
m_cycle(int connnum, int argc, char *argv[])
{
  leave(config_entries.defchannel);
  send_to_all( FLAGS_ALL, "I'm cycling.  Be right back.");
  sleep(1);

  /* probably on a cycle, we'd want the tcm to set
   * the key as well...
   */
  join();
}

void
m_die(int connnum, int argc, char *argv[])
{
  send_to_all( FLAGS_ALL, "I've been ordered to quit irc, goodbye.");
  print_to_server("QUIT :Dead by request!");
  tcm_log(L_ERR,
	  "DIEd by oper %s\n", connections[connnum].registered_nick);
  exit(1);
}

void
m_restart(int connnum, int argc, char *argv[])
{
  send_to_all( FLAGS_ALL, "I've been ordered to restart.");
  print_to_server("QUIT :Restart by request!");
  tcm_log(L_ERR,
	  "RESTART by oper %s", connections[connnum].registered_nick);
  sleep(1);
  execv(SPATH, NULL);
}

void
m_info(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "real server name [%s]",
       config_entries.rserver_name);
  if (config_entries.hybrid)
    print_to_socket(connections[connnum].socket, "Hybrid server version %d",
         config_entries.hybrid_version);
  else
    print_to_socket(connections[connnum].socket, "Non hybrid server");
}

void
m_locops(int connnum, int argc, char *argv[])
{
  char *p, dccbuff[MAX_BUFF];
  int i, len;

  if(argc >= 2)
  {
    p = dccbuff;
    for (i = 1; i < argc; i++)
    {
      len = sprintf(p, "%s ", argv[i]);
      p += len;
    }
    /* blow away last ' ' */
    *--p = '\0';
    if (dccbuff[0] == ':')
      print_to_server("LOCOPS :(%s) %s", connections[connnum].nick, dccbuff+1);
    else
      print_to_server("LOCOPS :(%s) %s", connections[connnum].nick, dccbuff);
  }
  else
    print_to_socket(connections[connnum].socket,
         "Really, it would help if you said something");
}

void
m_unkline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s <user@host>", argv[0]);
  else
  {
    tcm_log(L_NORM, "UNKLINE %s attempted by oper %s", argv[1],
        connections[connnum].registered_nick);
    send_to_all( FLAGS_VIEW_KLINES, "UNKLINE %s attempted by oper %s", 
                 argv[1], connections[connnum].registered_nick);
    print_to_server("UNKLINE %s",argv[1]);
  }
}

#ifndef NO_D_LINE_SUPPORT
void
m_dline(int connnum, int argc, char *argv[])
{
  char *p, reason[MAX_BUFF];
  int i, len;

  if(has_umode(connnum, FLAGS_DLINE) == 0)
  {
    print_to_socket(connections[connnum].socket,
		    "You do not have access to .dline");
    return;
  }
  if (argc >= 3)
  {
    p = reason;
    for (i = 2; i < argc; i++)
    {
      len = sprintf(p, "%s ", argv[i]);
      p += len;
    }
    /* blow away last ' ' */
    *--p = '\0';
    if (reason[0] == ':')
      log_kline("DLINE", argv[1], 0, connections[connnum].registered_nick, 
                reason+1);
    else
      log_kline("DLINE", argv[1], 0, connections[connnum].registered_nick,
                reason);
    send_to_all( FLAGS_ALL, "*** dline %s :%s by %s", argv[1],
                 reason, connections[connnum].registered_nick);

    if(has_umode(connnum, FLAGS_INVS) == 0)
    {
      strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
      strncat(reason, connections[connnum].nick,
              sizeof(reason)-strlen(reason));
      strncat(reason, ")", sizeof(reason)-strlen(reason));
    }
    print_to_server("DLINE %s :%s", argv[1], reason);
  }
}
#endif

#ifdef ENABLE_QUOTE
void
m_quote(int connnum, int argc, char *argv[])
{
  char dccbuff[MAX_BUFF];

  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <server message>", 
         argv[0]);
    return;
  }

  expand_args(dccbuff, MAX_BUFF-1, argc-1, argv+1);
  print_to_server("%s", dccbuff);
}
#endif

void
m_mem(int connnum, int argc, char *argv[])
{
  report_mem(connections[connnum].socket);
}

void m_nflood(int connnum, int argc, char *argv[])
{
  report_nick_flooders(connections[connnum].socket);
}

void
m_rehash(int connnum, int argc, char *argv[])
{
  send_to_all( FLAGS_ALL,
	       "*** rehash requested by %s", 
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    {
      print_to_server("STATS I");
      print_to_server("STATS Y");
    }
  else
    {
      print_to_server("STATS E");
      print_to_server("STATS F");
      print_to_server("STATS Y");
    }

  initopers();
  logclear();
}

void
m_trace(int connnum, int argc, char *argv[])
{
  send_to_all( FLAGS_ALL,
	       "Trace requested by %s",
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  inithash();
  print_to_server("STATS Y");
}

void
m_failures(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_failures(connections[connnum].socket, 7);
  else if (atoi(argv[1]) < 1)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [min failures]", argv[0]);
  else
    report_failures(connections[connnum].socket, atoi(argv[1]));
}

void
m_domains(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_domains(connections[connnum].socket, 5);
  else if (atoi(argv[1]) < 1)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [min users]", argv[0]);
  else
    report_domains(connections[connnum].socket, atoi(argv[1]));
}

void
m_events(int connnum, int argc, char *argv[])
{
  show_events(connections[connnum].socket);
}

void
m_nfind(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [-r] <wildcarded/regexp nick>", argv[0]);
  else if (argc == 2)
    list_nicks(connections[connnum].socket, argv[1], NO);
  else
    list_nicks(connections[connnum].socket, argv[2], YES);
#else
  if (argc <= 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded nick>", argv[0]);
  else
    list_nicks(connections[connnum].socket, argv[1], NO);
#endif
} 

void
m_list(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex userhost>", argv[0]);
  else if (argc == 2)
    list_users(connections[connnum].socket, argv[1], NO);
  else
    list_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded userhost>",
         argv[0]);
  else
    list_users(connections[connnum].socket, argv[1], NO);
#endif
}

void
m_ulist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex username>", argv[0]);
  else if (argc == 2)
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, buf, NO);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[2]);
    list_users(connections[connnum].socket, buf, YES);
  }
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded username>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}

void
m_hlist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex host>", argv[0]);
  else if (argc == 2)
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, buf, NO);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[2]);
    list_users(connections[connnum].socket, buf, YES);
  }
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s <wildcarded host>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}

/*
 * register_oper
 *
 * inputs	- socket
 * 		- password
 *		- who_did_command
 * output	- NONE
 * side effects	- user is warned they aren't an oper
 */

static void
register_oper(int connnum, char *password, char *who_did_command)
{
  if (password != NULL)
  {
    if (is_legal_pass(connnum, password))
    {
      int user;

      user = find_user_in_userlist(connections[connnum].registered_nick);

      print_to_socket(connections[connnum].socket,
		      "Set umodes from preferences");
      print_to_socket(connections[connnum].socket,
		      "Your current flags are now: %s",
		      type_show(userlist[user].type));

      if(has_umode(connnum, FLAGS_SUSPENDED))
      {
	print_to_socket(connections[connnum].socket,
 	                "You are suspended");
	send_to_all(FLAGS_ALL, "%s is suspended", who_did_command);
      }
      else
      {
	print_to_socket(connections[connnum].socket,
	                "You are now registered");
	send_to_all(FLAGS_ALL, "%s has registered", who_did_command);

	/* mark them as registered */
	userlist[user].type |= FLAGS_OPER;
      }
    }
    else
    {
      print_to_socket(connections[connnum].socket,"illegal password");
      send_to_all(FLAGS_ALL, "illegal password from %s", who_did_command);
    }
  }
  else
  {
    print_to_socket(connections[connnum].socket,"missing password");
  }
}

/*
 * list_opers
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current opers on socket
 */

static void 
list_opers(int sock)
{
  int i;
  
  for (i=0; i<MAXUSERS; i++)
  {
    if(userlist[i].user[0] == 0)
      break;

    print_to_socket(sock,
	 "(%s) %s@%s %s\n",
	 (userlist[i].usernick) ? userlist[i].usernick:"unknown",
	 userlist[i].user,
	 userlist[i].host,
	 type_show(userlist[i].type));
  }
}

/*
 * list_exemptions
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current exemptions on socket
 */

static void 
list_exemptions(int sock)
{
  int i, n;
  char buf[512];

  for (i=0; i<MAXHOSTS; i++)
  {
    if(hostlist[i].host[0] == 0)
      break;
    sprintf(buf, "%s@%s is exempted for:", hostlist[i].user, hostlist[i].host);
    for (n=0;actions[n].name[0];n++)
      if ((1 << n) & hostlist[i].type)
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " %s", actions[n].name);
    print_to_socket(sock,"%s", buf);
  }
}


/*
 * handle_save
 *
 * inputs	- socket
 *		- nick who did the command
 * output	- NONE
 * side effects	- save tcm prefs
 */

static void 
handle_save(int sock,char *nick)
{
  print_to_socket(sock, "Saving %s file", CONFIG_FILE);
  send_to_all( FLAGS_ALL, "%s is saving %s", nick, CONFIG_FILE);
  save_prefs();
}

struct dcc_command class_msgtab = {
 "class", NULL, {m_unregistered, m_class, m_class}
};
struct dcc_command classt_msgtab = {
 "classt", NULL, {m_unregistered, m_classt, m_classt}
};
struct dcc_command killlist_msgtab = {
 "killlist", NULL, {m_unregistered, m_killlist, m_killlist}
};
struct dcc_command kline_msgtab = {
 "kline", NULL, {m_unregistered, m_kline, m_kline}
};
struct dcc_command kclone_msgtab = {
 "kclone", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command kflood_msgtab = {
 "kflood", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command klink_msgtab = {
 "klink", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command kdrone_msgtab = {
 "kdrone", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command kbot_msgtab = {
 "kbot", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command kill_msgtab = {
 "kill", NULL, {m_unregistered, m_kill, m_kill}
};
struct dcc_command kspam_msgtab = {
 "kspam", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command register_msgtab = {
 "register", NULL, {m_register, m_register, m_register}
};
struct dcc_command opers_msgtab = {
 "opers", NULL, {m_unregistered, m_opers, m_opers}
};
struct dcc_command testline_msgtab = {
 "testline", NULL, {m_unregistered, m_testline, m_testline}
};
struct dcc_command uptime_msgtab = {
 "uptime", NULL, {m_uptime, m_uptime, m_uptime}
};
struct dcc_command exemptions_msgtab = {
 "exemptions", NULL, {m_unregistered, m_exemptions, m_exemptions}
};
struct dcc_command connections_msgtab = {
 "connections", NULL, {m_connections, m_connections, m_connections}
};
struct dcc_command whom_msgtab = {
 "whom", NULL, {m_connections, m_connections, m_connections}
};
struct dcc_command who_msgtab = {
 "who", NULL, {m_connections, m_connections, m_connections}
};
struct dcc_command disconnect_msgtab = {
 "disconnect", NULL, {m_unregistered, m_not_admin, m_disconnect}
};
struct dcc_command quit_msgtab = {
 "quit", NULL, {m_close, m_close, m_close}
};
struct dcc_command help_msgtab = {
 "help", NULL, {m_help, m_help, m_help}
};
struct dcc_command motd_msgtab = {
 "motd", NULL, {m_motd, m_motd, m_motd}
};
struct dcc_command save_msgtab = {
 "save", NULL, {m_unregistered, m_not_admin, m_save}
};
struct dcc_command close_msgtab = {
 "close", NULL, {m_close, m_close, m_close}
};
struct dcc_command op_msgtab = {
 "op", NULL, {m_unregistered, m_op, m_op}
};
struct dcc_command cycle_msgtab = {
 "cycle", NULL, {m_unregistered, m_cycle, m_cycle}
};
struct dcc_command die_msgtab = {
 "die", NULL, {m_unregistered, m_not_admin, m_die}
};
struct dcc_command restart_msgtab = { 
 "restart", NULL, {m_unregistered, m_not_admin, m_restart}
};
struct dcc_command info_msgtab = {
 "info", NULL, {m_info, m_info, m_info}
};
struct dcc_command locops_msgtab = {
 "locops", NULL, {m_unregistered, m_locops, m_locops}
};
struct dcc_command unkline_msgtab = {
 "unkline", NULL, {m_unregistered, m_unkline, m_unkline}
};
#ifndef NO_D_LINE_SUPPORT
struct dcc_command dline_msgtab = {
 "dline", NULL, {m_unregistered, m_dline, m_dline}
};
#endif
#ifdef ENABLE_QUOTE
struct dcc_command quote_msgtab = {
 "quote", NULL, {m_unregistered, m_not_admin, m_quote}
};
#endif
struct dcc_command mem_msgtab = {
 "mem", NULL, {m_unregistered, m_not_admin, m_mem}
};
struct dcc_command nflood_msgtab = {
 "nflood", NULL, {m_unregistered, m_nflood, m_nflood}
};
struct dcc_command rehash_msgtab = {
 "rehash", NULL, {m_unregistered, m_not_admin, m_rehash}
};
struct dcc_command trace_msgtab = {
 "trace", NULL, {m_unregistered, m_trace, m_trace}
};
struct dcc_command failures_msgtab = {
 "failures", NULL, {m_unregistered, m_failures, m_failures}
};
struct dcc_command domains_msgtab = {
 "domains", NULL, {m_unregistered, m_domains, m_domains}
};
struct dcc_command events_msgtab = {
 "events", NULL, {m_unregistered, m_events, m_events}
};
struct dcc_command nfind_msgtab = {
 "nfind", NULL, {m_unregistered, m_nfind, m_nfind}
};
struct dcc_command list_msgtab = {
 "list", NULL, {m_unregistered, m_list, m_list}
};
struct dcc_command ulist_msgtab = {
 "ulist", NULL, {m_unregistered, m_ulist, m_ulist}
};
struct dcc_command hlist_msgtab = {
 "hlist", NULL, {m_unregistered, m_hlist, m_hlist}
};

void 
init_commands(void)
{
  add_dcc_handler(&class_msgtab);
  add_dcc_handler(&classt_msgtab);
  add_dcc_handler(&killlist_msgtab);
  add_dcc_handler(&kline_msgtab);
  add_dcc_handler(&kclone_msgtab);
  add_dcc_handler(&kflood_msgtab);
  add_dcc_handler(&klink_msgtab);
  add_dcc_handler(&kdrone_msgtab);
  add_dcc_handler(&kbot_msgtab);
  add_dcc_handler(&kill_msgtab);
  add_dcc_handler(&kspam_msgtab);
  add_dcc_handler(&register_msgtab);
  add_dcc_handler(&opers_msgtab);
  add_dcc_handler(&testline_msgtab);
  add_dcc_handler(&exemptions_msgtab);
  add_dcc_handler(&connections_msgtab);
  add_dcc_handler(&whom_msgtab);
  add_dcc_handler(&who_msgtab);
  add_dcc_handler(&disconnect_msgtab);
  add_dcc_handler(&quit_msgtab);
  add_dcc_handler(&help_msgtab);
  add_dcc_handler(&motd_msgtab);
  add_dcc_handler(&save_msgtab);
  add_dcc_handler(&close_msgtab);
  add_dcc_handler(&op_msgtab);
  add_dcc_handler(&cycle_msgtab);
  add_dcc_handler(&die_msgtab);
  add_dcc_handler(&restart_msgtab);
  add_dcc_handler(&info_msgtab);
  add_dcc_handler(&locops_msgtab);
  add_dcc_handler(&unkline_msgtab);
#ifndef NO_D_LINE_SUPPORT
  add_dcc_handler(&dline_msgtab);
#endif
#ifdef ENABLE_QUOTE
  add_dcc_handler(&quote_msgtab);
#endif
  add_dcc_handler(&mem_msgtab);
  add_dcc_handler(&nflood_msgtab);
  add_dcc_handler(&rehash_msgtab);
  add_dcc_handler(&trace_msgtab);
  add_dcc_handler(&failures_msgtab);
  add_dcc_handler(&domains_msgtab);
  add_dcc_handler(&events_msgtab);
  add_dcc_handler(&nfind_msgtab);
  add_dcc_handler(&list_msgtab);
  add_dcc_handler(&ulist_msgtab);
  add_dcc_handler(&hlist_msgtab);
  add_dcc_handler(&uptime_msgtab);
}

/*
 * is_legal_pass()
 *
 * inputs       - user
 *              - host
 *              - password
 *              - int connect id
 * output       - oper type if legal 0 if not
 * side effects - NONE
 */

static int
is_legal_pass(int connect_id, char *password)
{
  int i;

  for(i=0; userlist[i].user && userlist[i].host[0]; i++)
    {
      if ((match(userlist[i].user,connections[connect_id].user) == 0) &&
          (wldcmp(userlist[i].host,connections[connect_id].host) == 0))
        {
	  /* 
	   * userlist entries discovered from stats O
	   * has no valid password field. ignore them.
	   */

          if(userlist[i].password[0])
            {
#ifdef USE_CRYPT
              if(strcmp((char*)crypt(password,userlist[i].password),
                         userlist[i].password) == 0)
	      {
                strncpy(connections[connect_id].registered_nick,
                        userlist[i].usernick,
                        MAX_NICK);

		return 1;
	      }
#else
              if(strcmp(userlist[i].password,password) == 0)
	      {
                strncpy(connections[connect_id].registered_nick,
                        userlist[i].usernick,
                        MAX_NICK);

		return 1;
	      }
#endif
            }
        }
    }
  return(0);
}

/*
 * print_help()
 *
 * inputs       - socket, help_text to use
 * output       - none
 * side effects - prints help file to user
 */

static void
print_help(int sock,char *text)
{
  FILE *userfile;
  char line[MAX_BUFF];
  char help_file[MAX_BUFF];

  if(!text || (*text == '\0') || (*text == '?'))
    {
      if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
        {
          print_to_socket(sock,"Help is not currently available");
          return;
        }
    }
  else
    {
      while(*text == ' ')
        text++;

      if ((*text == '\0') || (*text == '?'))
        {
          if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
            {
              print_to_socket(sock,"Help is not currently available");
              return;
            }
        }

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( (userfile = fopen(help_file,"r")) == NULL)
        {
          print_to_socket(sock,
			  "Help for '%s' is not currently available",text);
          return;
        }
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      print_to_socket(sock, "%s", line);
    }
  fclose(userfile);
}
