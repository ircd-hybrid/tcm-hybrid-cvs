/* $Id: dcc_commands.c,v 1.144 2002/09/11 17:55:39 db Exp $ */

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

static void register_oper(struct connection *,
			  char *password, char *who_did_command);
int is_legal_pass(struct connection *, char *password);
static void print_help(struct connection *connection_p, char *text);

static void m_class(struct connection *connection_p, int argc, char *argv[]);
static void m_classt(struct connection *connection_p, int argc, char *argv[]);
static void m_killlist(struct connection *connection_p, int argc,
		       char *argv[]);
static void m_kline(struct connection *connection_p, int argc, char **argv);
static void m_kill(struct connection *connection_p, int argc, char *argv[]);
static void m_kaction(struct connection *connection_p, int argc, char *argv[]);
static void m_register(struct connection *connection_p, int argc,
		       char *argv[]);
static void m_opers(struct connection *connection_p, int argc, char *argv[]);
static void m_testline(struct connection *connection_p, int argc,
		       char *argv[]);
static void m_uptime(struct connection *connection_p, int argc, char *argv[]);
static void m_exempts(struct connection *connection_p, int argc, char *argv[]);
static void m_connections(struct connection *connection_p, int argc,
			  char *argv[]);
static void m_disconnect(struct connection *connection_p, int argc,
			 char *argv[]);
static void m_events(struct connection *connection_p, int argc, char *argv[]);
static void m_help(struct connection *connection_p, int argc, char *argv[]);
static void m_motd(struct connection *connection_p, int argc, char *argv[]);
static void m_save(struct connection *connection_p, int argc, char *argv[]);
static void m_close(struct connection *connection_p, int argc, char *argv[]);
static void m_op(struct connection *connection_p, int argc, char *argv[]);
static void m_cycle(struct connection *connection_p, int argc, char *argv[]);
static void m_die(struct connection *connection_p, int argc, char *argv[]);
static void m_restart(struct connection *connection_p, int argc, char *argv[]);
static void m_info(struct connection *connection_p, int argc, char *argv[]);
static void m_locops(struct connection *connection_p, int argc, char *argv[]);
static void m_unkline(struct connection *connection_p, int argc, char *argv[]);
static void m_dline(struct connection *connection_p, int argc, char *argv[]);
#ifdef ENABLE_QUOTE
static void m_quote(struct connection *connection_p, int argc, char *argv[]);
#endif
static void m_mem(struct connection *connection_p, int argc, char *argv[]);
static void m_nflood(struct connection *connection_p, int argc, char *argv[]);
static void m_rehash(struct connection *connection_p, int argc, char *argv[]);
static void m_trace(struct connection *connection_p, int argc, char *argv[]);
static void m_failures(struct connection *connection_p, int argc,
		       char *argv[]);
static void m_domains(struct connection *connection_p, int argc, char *argv[]);
static void m_nfind(struct connection *connection_p, int argc, char *argv[]);
static void m_list(struct connection *connection_p, int argc, char *argv[]);
static void m_gecos(struct connection *connection_p, int argc, char *argv[]);
static void m_ulist(struct connection *connection_p, int argc, char *argv[]);
static void m_hlist(struct connection *connection_p, int argc, char *argv[]);

void
m_class(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s <class name>", argv[0]);
  else
    list_class(connection_p, argv[1], NO);
}

void
m_classt(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s <class name>", argv[0]);
  else
    list_class(connection_p, argv[1], YES);
}

void
m_killlist(struct connection *connection_p, int argc, char *argv[])
{
  char reason[MAX_REASON];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc < 4 && (strcasecmp(argv[1], "-r") == 0)))
  {
    send_to_connection(connection_p,
		       "Usage: .killlist [-r] <wildcarded/regex userhost> <reason>");
    return;
  }

  if (argc >= 4)
  {
    expand_args(reason, MAX_REASON, argc-3, argv+3);
  }
#else
  if (argc < 2)
  {
    send_to_connection(connection_p,
		       "Usage: %s <wildcarded userhost> <reason>",
		       argv[0]);
    return;
  }

  if (argc >= 3)
  {
    expand_args(reason, sizeof(reason), argc-2, argv+2);
  }
#endif
  else
    snprintf(reason, sizeof(reason), "No reason");

  if((connection_p->type & FLAGS_INVS) == 0)
  {
    strncat(reason, " (requested by ", MAX_REASON - strlen(reason));
    strncat(reason, connection_p->registered_nick,
            MAX_REASON - strlen(reason));
    strncat(reason, ")", MAX_REASON - strlen(reason));
  }

#ifdef HAVE_REGEX_H
  if (strcasecmp(argv[1], "-r") == 0)
  {
    send_to_all(NULL, FLAGS_ALL, "*** killlist %s :%s by %s", argv[2],
                reason, connection_p->registered_nick);
    kill_or_list_users(connection_p, argv[2], YES, YES, reason);
  }
  else
#endif
  {
    send_to_all(NULL, FLAGS_ALL, "*** killlist %s :%s by %s", argv[1],
                reason, connection_p->registered_nick);
    kill_or_list_users(connection_p, argv[1], NO, YES, reason);
  }
}

void
m_kline(struct connection *connection_p, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  int kline_time;

  if (!(connection_p->type & FLAGS_KLINE))
  {
    send_to_connection(connection_p,
                       "You need the K flag to use %s", argv[0]);
    return;
  }

  if (argc < 3)
    send_to_connection(connection_p,
		       "Usage: %s [time] <[nick]|[user@host]> [reason]",
		       argv[0]);
  else
  {
    if ((kline_time = atoi(argv[1])))
    {
      if (argc >= 4)
      {
	expand_args(buff, MAX_BUFF, argc-3, argv+3);
      }
      else
        snprintf(buff, sizeof(buff), "No reason");
      do_a_kline(kline_time, argv[2], buff, 
                 connection_p->registered_nick);
    }
    else
    {
      if (argc >= 3)
      {
	expand_args(buff, MAX_BUFF, argc-2, argv+2);
      }
      do_a_kline(0, argv[1], buff,
		 connection_p->registered_nick);
    }
  }
}

void
m_kill(struct connection *connection_p, int argc, char *argv[])
{
  char reason[MAX_REASON];

  if (argc < 2)
  {
    send_to_connection(connection_p,
		       "Usage: %s <nick|user@host [reason]", argv[0]);
    return;
  }
  else if (argc == 2)
    snprintf(reason, MAX_REASON, "No reason");
  else
  {
    expand_args(reason, MAX_REASON, argc-2, argv+2);
  }

  send_to_all(NULL, FLAGS_VIEW_KLINES, "*** kill %s :%s by %s",
              argv[1], reason, connection_p->registered_nick);
  log_kline("KILL", argv[1], 0, connection_p->registered_nick, reason);

  if((connection_p->type & FLAGS_INVS) == 0)
  {
    strncat(reason, " (requested by ", MAX_REASON - 1 - strlen(reason));
    strncat(reason, connection_p->registered_nick,
            MAX_REASON - 1 - strlen(reason));
    strncat(reason, ")", MAX_REASON - strlen(reason));
  }

  send_to_server("KILL %s :%s", argv[1], reason);
}

void
m_kaction(struct connection *connection_p, int argc, char *argv[])
{
  char *userhost;
  char *p;
  int actionid;

  if(argc < 2)
  {
    send_to_connection(connection_p,
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

    send_to_server("KLINE %s :%s", userhost, actions[actionid].reason);
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

    send_to_server("KLINE %s %s :%s", 
		   argv[1], userhost, actions[actionid].reason);
  }
}

void
m_register(struct connection *connection_p, int argc, char *argv[])
{
  if(connection_p->type & FLAGS_OPER)
  {
    send_to_connection(connection_p, "You are already registered.");
    return;
  }

  if (argc != 2)
    send_to_connection(connection_p, "Usage: %s <password>", argv[0]);
  else
    register_oper(connection_p, argv[1], connection_p->nick);
}

void m_opers(struct connection *connection_p, int argc, char *argv[])
{
  dlink_node *ptr;
  struct oper_entry *user;

  DLINK_FOREACH(ptr, user_list.head)
  {
    user = ptr->data;

    send_to_connection(connection_p, "(%s) %s@%s %s",
		       user->usernick, user->username, user->host,
		       type_show(user->type));
  }
}

void
m_testline(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
  {
    send_to_connection(connection_p, "Usage: %s <mask>", argv[0]);
    return;
  }
  if (config_entries.testline_cnctn != NULL)
  {
    send_to_connection(connection_p, "Error: Pending testline on %s", config_entries.testline_umask);
    return;
  }

  snprintf(config_entries.testline_umask, sizeof(config_entries.testline_umask), "%s", argv[1]);
  config_entries.testline_cnctn = connection_p;

  send_to_server("TESTLINE %s", argv[1]);
}

void
m_uptime(struct connection *connection_p, int argc, char *argv[])
{
  report_uptime(connection_p);
}

void
m_exempts(struct connection *connection_p, int argc, char *argv[])
{
  dlink_node *ptr;
  struct exempt_entry *exempt;
  char buf[512];
  int n;

  DLINK_FOREACH(ptr, exempt_list.head)
  {
    exempt = ptr->data;
    sprintf(buf, "%s@%s is exempted for:", exempt->username, exempt->host);

    for(n = 0; actions[n].name[0] != '\0'; n++)
    {
      if((1 << n) & exempt->type)
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), 
                 " %s", actions[n].name);
    }

    send_to_connection(connection_p, "%s", buf);
  }
}

void
m_connections(struct connection *connection_p, int argc, char *argv[])
{
  list_connections(connection_p);
}

void
m_disconnect(struct connection *connection_p, int argc, char *argv[])
{
  struct connection *found_user;

  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s <nick>", argv[0]);
  else
  {
    found_user = find_user_in_connections(argv[1]);

    if(found_user != NULL)
    {
      send_to_connection(connection_p,
			 "Disconnecting oper %s", connection_p->nick);
      send_to_connection(found_user,
			 "You have been disconnected by oper %s",
			 connection_p->registered_nick);
      close_connection(found_user);
    }
  }
}

void
m_help(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s ?", argv[0]);
  else
    print_help(connection_p, argv[1]);
}

void
m_motd(struct connection *connection_p, int argc, char *argv[])
{
  print_motd(connection_p);
}

void
m_save(struct connection *connection_p, int argc, char *argv[])
{
  send_to_all(NULL, FLAGS_ALL, "%s is saving %s and preferences",
              connection_p->registered_nick, CONFIG_FILE);
  save_prefs();
}

void
m_close(struct connection *connection_p, int argc, char *argv[])
{
  send_to_connection(connection_p, "Closing connection");
  close_connection(connection_p);
}

void
m_op(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s <nick>", argv[0]);
  else
    op(config_entries.channel, argv[1]);
}

void
m_cycle(struct connection *connection_p, int argc, char *argv[])
{
  leave(config_entries.channel);
  send_to_all(NULL, FLAGS_ALL, "I'm cycling.  Be right back.");
  sleep(1);

  /* probably on a cycle, we'd want the tcm to set
   * the key as well...
   */
  join();
}

void
m_die(struct connection *connection_p, int argc, char *argv[])
{
  send_to_all(NULL, FLAGS_ALL, "I've been ordered to quit irc, goodbye.");
  send_to_server("QUIT :Dead by request!");
  tcm_log(L_ERR, "DIEd by oper %s", connection_p->registered_nick);
  exit(1);
}

void
m_restart(struct connection *connection_p, int argc, char *argv[])
{
  send_to_all(NULL, FLAGS_ALL, "I've been ordered to restart.");
  send_to_server("QUIT :Restart by request!");
  tcm_log(L_ERR, "RESTART by oper %s", connection_p->registered_nick);
  sleep(1);
  execv(SPATH, NULL);
}

void
m_info(struct connection *connection_p, int argc, char *argv[])
{
  send_to_connection(connection_p, "real server name [%s]",
		     tcm_status.my_server);
  if (config_entries.hybrid)
    send_to_connection(connection_p, "Hybrid server version %d",
         config_entries.hybrid_version);
  else
    send_to_connection(connection_p, "Non hybrid server");
}

void
m_locops(struct connection *connection_p, int argc, char *argv[])
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
      send_to_server("LOCOPS :(%s) %s", connection_p->nick, dccbuff+1);
    else
      send_to_server("LOCOPS :(%s) %s", connection_p->nick, dccbuff);
  }
  else
    send_to_connection(connection_p,
		       "Really, it would help if you said something");
}

void
m_unkline(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s <user@host>", argv[0]);
  else
  {
    tcm_log(L_NORM, "UNKLINE %s attempted by oper %s",
            argv[1], connection_p->registered_nick);
    send_to_all(NULL, FLAGS_VIEW_KLINES, "UNKLINE %s attempted by oper %s", 
                 argv[1], connection_p->registered_nick);
    send_to_server("UNKLINE %s",argv[1]);
  }
}

#ifndef NO_D_LINE_SUPPORT
void
m_dline(struct connection *connection_p, int argc, char *argv[])
{
  char *p, reason[MAX_BUFF];
  int i, len;

  if(connection_p->type & FLAGS_DLINE)
  {
    send_to_connection(connection_p, "You do not have access to .dline");
    return;
  }
  if(argc >= 3)
  {
    p = reason;
    for (i = 2; i < argc; i++)
    {
      len = sprintf(p, "%s ", argv[i]);
      p += len;
    }
    /* blow away last ' ' */
    *--p = '\0';
    if(reason[0] == ':')
      log_kline("DLINE", argv[1], 0, connection_p->registered_nick, 
                reason+1);
    else
      log_kline("DLINE", argv[1], 0, connection_p->registered_nick,
                reason);
    send_to_all(NULL, FLAGS_ALL, "*** dline %s :%s by %s", argv[1],
		reason, connection_p->registered_nick);

    if((connection_p->type & FLAGS_INVS) == 0)
    {
      strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
      strncat(reason, connection_p->nick,
              sizeof(reason)-strlen(reason));
      strncat(reason, ")", sizeof(reason)-strlen(reason));
    }
    send_to_server("DLINE %s :%s", argv[1], reason);
  }
}
#endif

#ifdef ENABLE_QUOTE
void
m_quote(struct connection *connection_p, int argc, char *argv[])
{
  char dccbuff[MAX_BUFF];

  if(argc < 2)
  {
    send_to_connection(connection_p, "Usage: %s <server message>", argv[0]);
    return;
  }

  expand_args(dccbuff, MAX_BUFF, argc-1, argv+1);
  send_to_server("%s", dccbuff);
}
#endif

void
m_mem(struct connection *connection_p, int argc, char *argv[])
{
  report_mem(connection_p);
}

void m_nflood(struct connection *connection_p, int argc, char *argv[])
{
  report_nick_flooders(connection_p);
}

void
m_rehash(struct connection *connection_p, int argc, char *argv[])
{
  send_to_all(NULL, FLAGS_ALL,
	      "*** rehash requested by %s", 
	      connection_p->registered_nick[0] ?
	      connection_p->registered_nick :
	      connection_p->nick);

  reload_userlist();
}

void
m_trace(struct connection *connection_p, int argc, char *argv[])
{
  send_to_all(NULL, FLAGS_ALL,
	      "Trace requested by %s",
	      connection_p->registered_nick[0] ?
	      connection_p->registered_nick :
	      connection_p->nick);

  clear_hash();
  clear_bothunt();
}

void
m_failures(struct connection *connection_p, int argc, char *argv[])
{
  if(argc < 2)
    report_failures(connection_p, 7);
  else if(atoi(argv[1]) < 1)
    send_to_connection(connection_p, "Usage: %s [min failures]", argv[0]);
  else
    report_failures(connection_p, atoi(argv[1]));
}

void
m_domains(struct connection *connection_p, int argc, char *argv[])
{
  if(argc < 2)
    report_domains(connection_p, 5);
  else if(atoi(argv[1]) < 1)
    send_to_connection(connection_p, "Usage: %s [min users]", argv[0]);
  else
    report_domains(connection_p, atoi(argv[1]));
}

void
m_events(struct connection *connection_p, int argc, char *argv[])
{
  show_events(connection_p);
}

void
m_nfind(struct connection *connection_p, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    send_to_connection(connection_p,
		    "Usage: %s [-r] <wildcarded/regexp nick>", argv[0]);
  else if(argc == 2)
    list_nicks(connection_p, argv[1], NO);
  else
    list_nicks(connection_p, argv[2], YES);
#else
  if(argc <= 2)
    send_to_connection(connection_p,
		       "Usage: %s <wildcarded nick>", argv[0]);
  else
    list_nicks(connection_p, argv[1], NO);
#endif
} 

void
m_list(struct connection *connection_p, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    send_to_connection(connection_p,
	"Usage: %s [-r] <wildcarded/regex userhost>", argv[0]);
  else if(argc == 2)
    kill_or_list_users(connection_p, argv[1], NO, NO, NULL);
  else
    kill_or_list_users(connection_p, argv[2], YES, NO, NULL);
#else
  if(argc < 2)
    send_to_connection(connection_p,
		       "Usage: %s <wildcarded userhost>",
         argv[0]);
  else
    kill_or_list_users(connection_p, argv[1], NO, NO, NULL);
#endif
}

void
m_gecos(struct connection *connection_p, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    send_to_connection(connection_p,
        "Usage: %s [-r] <wildcarded/regex gecos>", argv[0]);
  else if(argc == 2)
    list_gecos(connection_p, argv[1], NO);
  else
    list_gecos(connection_p, argv[2], YES);
#else
  if(argc < 2)
    send_to_connections(connection_p,
                        "Usage: %s <wildcarded gecos>",
         argv[0]);
  else
    list_gecos(connection_p, argv[1], NO);
#endif
}

void
m_ulist(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    send_to_connection(connection_p,
		       "Usage: %s [-r] <wildcarded/regex username>", argv[0]);
  else if(argc == 2)
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    kill_or_list_users(connection_p, buf, NO, NO, NULL);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[2]);
    kill_or_list_users(connection_p, buf, YES, NO, NULL);
  }
#else
  if(argc < 2)
    send_to_connection(&connection_p, "Usage: %s <wildcarded username>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    kill_or_list_users(connection_p, argv[1], NO, NO, NULL);
  }
#endif
}

void
m_hlist(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    send_to_connection(connection_p, "Usage: %s [-r] <wildcarded/regex host>",
		       argv[0]);
  else if(argc == 2)
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    kill_or_list_users(connection_p, buf, NO, NO, NULL);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[2]);
    kill_or_list_users(connection_p, buf, YES, NO, NULL);
  }
#else
  if(argc < 2)
    send_to_connection(connection_p, "Usage: %s <wildcarded host>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    kill_or_list_users(connection_p, argv[1], NO, NO, NULL);
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
register_oper(struct connection *connection_p, char *password,
	      char *who_did_command)
{
  if(password != NULL)
  {
    if(is_legal_pass(connection_p, password))
    {
      send_to_connection(connection_p,
			 "Your current flags are: %s",
			 type_show(connection_p->type));

      if(connection_p->type & FLAGS_SUSPENDED)
      {
	send_to_connection(connection_p, "You are suspended");
	send_to_all(NULL, FLAGS_ALL, "%s is suspended", who_did_command);
      }
      else
      {
	send_to_connection(connection_p, "You are now registered");
	send_to_all(NULL, FLAGS_ALL, "%s has registered", who_did_command);

	/* mark them as registered */
	connection_p->type |= FLAGS_OPER;
      }
    }
    else
    {
      send_to_all(NULL, FLAGS_ALL,
		  "illegal password from %s", who_did_command);
    }
  }
  else
  {
    send_to_connection(connection_p, "missing password");
  }
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
 "exemptions", NULL, {m_unregistered, m_exempts, m_exempts}
};
struct dcc_command exempts_msgtab = {
 "exempts", NULL, {m_unregistered, m_exempts, m_exempts}
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
struct dcc_command gecos_msgtab = {
 "gecos", NULL, {m_unregistered, m_gecos, m_gecos}
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
  add_dcc_handler(&exempts_msgtab);
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
  add_dcc_handler(&gecos_msgtab);
  add_dcc_handler(&ulist_msgtab);
  add_dcc_handler(&hlist_msgtab);
  add_dcc_handler(&uptime_msgtab);
}

/*
 * is_legal_pass()
 *
 * inputs       - pointer to struct connection
 *              - password
 * output       - oper type if legal 0 if not
 * side effects - NONE
 */
int
is_legal_pass(struct connection *connection_p, char *password)
{
  dlink_node *ptr;
  struct oper_entry *user;

  DLINK_FOREACH(ptr, user_list.head)
  {
    user = ptr->data;

    if((match(user->username, connection_p->username) == 0) &&
       (wldcmp(user->host, connection_p->host) == 0) &&
       (user->password[0] != '\0'))
    {
#ifdef USE_CRYPT
      if(strcmp((char *)crypt(password, user->password),
                user->password) == 0)
#else
      if(strcmp(user->password, password) == 0)
#endif
      {
        strlcpy(connection_p->registered_nick, user->usernick, 
                sizeof(connection_p->registered_nick));
	return YES;
      }
    }
  }

  return NO;
}

/*
 * print_help()
 *
 * inputs       - pointer to connection to use
 * output       - none
 * side effects - prints help file to user
 */

static void
print_help(struct connection *connection_p, char *text)
{
  FILE *userfile;
  char line[MAX_BUFF];
  char help_file[MAX_BUFF];

  if(!text || (*text == '\0') || (*text == '?'))
    {
      if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
        {
          send_to_connection(connection_p,"Help is not currently available");
          return;
        }
    }
  else
    {
      while(*text == ' ')
        text++;

      if((*text == '\0') || (*text == '?'))
        {
          if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
            {
              send_to_connection(connection_p,
				 "Help is not currently available");
              return;
            }
        }

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( (userfile = fopen(help_file,"r")) == NULL)
        {
          send_to_connection(connection_p,
			  "Help for '%s' is not currently available",text);
          return;
        }
    }

  while (fgets(line, MAX_BUFF, userfile))
    {
      send_to_connection(connection_p, "%s", line);
    }
  fclose(userfile);
}
