/* $Id: dcc_commands.c,v 1.159 2004/06/03 20:39:10 bill Exp $ */

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
#include "tcm_io.h"
#include "wild.h"
#include "match.h"
#include "actions.h"
#include "handler.h"
#include "hash.h"
#include "tools.h"
#include "client_list.h"

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
static void m_undline(struct connection *connection_p, int argc, char *argv[]);
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
static void m_smartlist(struct connection *connection_p, int argc, char *argv[]);
#ifdef DEBUGMODE
static void m_sysnotice(struct connection *connection_p, int argc, char *argv[]);
#endif
static void m_xline(struct connection *connection_p, int argc, char *argv[]);
static void m_unxline(struct connection *connection_p, int argc, char *argv[]);
static void m_jupe(struct connection *connection_p, int argc, char *argv[]);
static void m_unjupe(struct connection *connection_p, int argc, char *argv[]);

void
m_class(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2 ||
      (strcasecmp(argv[1], "-l") == 0 && argc < 4))
  {
    send_to_connection(connection_p, "Usage: %s [-l list] <class>", argv[0]);
    return;
  }

  if (strcasecmp(argv[1], "-l") == 0)
    list_class(connection_p, argv[3], NO, argv[2]);
  else
    list_class(connection_p, argv[1], NO, NULL);
}

void
m_classt(struct connection *connection_p, int argc, char *argv[])
{
  if (argc < 2)
    send_to_connection(connection_p, "Usage: %s <class>", argv[0]);
  else
    list_class(connection_p, argv[1], YES, NULL);
}

void
m_killlist(struct connection *connection_p, int argc, char *argv[])
{
  char reason[MAX_REASON], pattern[MAX_USER + MAX_HOST + 2], list[BUFFERSIZE], c;
  const char *usage;
  int regex = NO, ro;

  reason[0] = list[0] = pattern[0] = c = '\0';
  optind = 1;
  ro = 1;

#ifdef HAVE_REGEX_H
  usage = "Usage: %s [-r] <[-l list name]|[pattern]> [reason]";

  while ((c = getopt(argc, argv, "l:r")) != -1)
#else
  usage = "Usage: %s <[-l list name]|[pattern]> [reason]";

  while ((c = getopt(argc, argv, "l:")) != -1)
#endif
  {
    switch (c)
    {
      case 'l':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(list, optarg, sizeof(list));
        break;

#ifdef HAVE_REGEX_H
      case 'r':
        regex = YES;
        break;
#endif

      case '?':
      default:
        break;
    }
  }

  if (argc == 1)
  {
    send_to_connection(connection_p, usage, argv[0]);
    return;
  }

  /* only bother if we're not killing a client list */
  if (list[0] == '\0')
  {
    strlcpy(pattern, argv[argc-1], sizeof(pattern));
    ro++;
  }
  else
    ro += 2;

  if (regex == YES)
    ro++;

  expand_args(reason, MAX_REASON, argc-ro, argv+ro);

  if((connection_p->type & FLAGS_INVS) == 0)
  {
    if (reason[0] == '\0')
      snprintf(reason, sizeof(reason), "No reason");

    strncat(reason, " [", MAX_REASON - strlen(reason));
    strncat(reason, connection_p->registered_nick,
            MAX_REASON - strlen(reason));
    strncat(reason, "]", MAX_REASON - strlen(reason));
  }

  send_to_all(NULL, FLAGS_ALL, "*** killlist %s :%s by %s",
              list[0] ? list : pattern,
              reason, connection_p->registered_nick);
  kill_or_list_users(connection_p, list[0] ? NULL : pattern,
                     regex, KILL, list[0] ? list : NULL,
                     reason[0] ? reason : NULL);
}

void
m_kline(struct connection *connection_p, int argc, char *argv[])
{
  char buff[MAX_BUFF], *userhost = NULL;
  int kline_time, idx;
  struct client_list *list;
  struct user_entry *user;
  dlink_node *ptr;

  if (!(connection_p->type & FLAGS_KLINE))
  {
    send_to_connection(connection_p,
                       "You need the K flag to use %s", argv[0]);
    return;
  }

  /*
   * .kline
   */
  if (argc < 2)
    send_to_connection(connection_p,
		       "Usage: %s [time] <[nick]|[user@host]|[-l listname]> [reason]",
		       argv[0]);
  else
  {
    if ((kline_time = atoi(argv[1])))
    {
      /* .kline 1440 -l lamers */
      /* .kline 1440 -l drones Drones */
      /* .kline 1440 billy-jon a b c */
      if (!strcasecmp(argv[2], "-l"))
      {
        if ((idx = find_list(argv[3])) == -1)
        {
          send_to_connection(connection_p, "No such list.");
          return;
        }
        if (argc >= 5)
          expand_args(buff, sizeof(buff), argc-4, argv+4);
        else
          snprintf(buff, sizeof(buff), "No reason");
        list = &client_lists[idx];
        DLINK_FOREACH(ptr, list->dlink.head)
        {
          user = ptr->data;
          if ((userhost = get_method_userhost(-1, NULL, user->username,
                                              user->host)) == NULL)
          {
            send_to_connection(connection_p, "Error in get_method_userhost().  Aborting...");
            continue;
          }
          send_to_server("KLINE %s %s :%s", argv[1], userhost, buff);
        }
      }
      /* .kline 1440 billy-jon */
      /* .kline 1440 billy-jon a b c */
      else
      {
        if (argc >= 4)
	  expand_args(buff, MAX_BUFF, argc-3, argv+3);
        else
          snprintf(buff, sizeof(buff), "No reason");
      }
      do_a_kline(kline_time, argv[2], buff, connection_p);
    }
    else
    {
      /* .kline -l lamers */
      /* .kline -l drones Drones */
      if (!strcasecmp(argv[1], "-l"))
      {
        if ((idx = find_list(argv[2])) == -1)
        {
          send_to_connection(connection_p, "No such list.");
          return;
        }
        if (argc >= 4)
          expand_args(buff, sizeof(buff), argc-3, argv+3);
        else
          snprintf(buff, sizeof(buff), "No reason");
        list = &client_lists[idx];
        DLINK_FOREACH(ptr, list->dlink.head)
        {
          user = ptr->data;
          if ((userhost = get_method_userhost(-1, NULL, user->username,
                                              user->host)) == NULL)
          {
            send_to_connection(connection_p, "Error in get_method_userhost().  Aborting...");
            continue;
          }
          send_to_server("KLINE %s :%s", userhost, buff);
        }
      }
      /* .kline billy-jon */
      /* .kline billy-jon a b c */
      /* .kline *@ummm.E a b c */
      else
      {
        if (argc >= 3)
          expand_args(buff, sizeof(buff), argc-2, argv+2);
        else
          snprintf(buff, sizeof(buff), "No reason");
        do_a_kline(0, argv[1], buff, connection_p);
      }
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
		       "Usage: %s <nick> [reason]", argv[0]);
    return;
  }
  else if (argc == 2)
    snprintf(reason, MAX_REASON, "No reason");
  else
    expand_args(reason, MAX_REASON, argc-2, argv+2);

  send_to_all(NULL, FLAGS_VIEW_KLINES, "*** kill %s :%s by %s",
              argv[1], reason, connection_p->registered_nick);
  log_kline("KILL", argv[1], 0, connection_p->registered_nick, reason);

  if((connection_p->type & FLAGS_INVS) == 0)
  {
    strncat(reason, " [", MAX_REASON - 1 - strlen(reason));
    strncat(reason, connection_p->registered_nick,
            MAX_REASON - 1 - strlen(reason));
    strncat(reason, "]", MAX_REASON - strlen(reason));
  }

  send_to_server("KILL %s :%s", argv[1], reason);
}

void
m_kaction(struct connection *connection_p, int argc, char *argv[])
{
  char *userhost;
  char *p;
  int actionid;
  struct client_list *list;
  dlink_node *ptr;
  struct user_entry *user;

  if(argc < 2)
  {
    send_to_connection(connection_p,
		       "Usage: %s [time] <[nick]|[user@host]|[-l listname]>", argv[0]);
    return;
  }

  /* skip past .k bit */
  actionid = find_action(argv[0]+2);

  /* .kdrone bill@ummm.E */
  /* .kdrone billy-jon */
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
    /* .kdrone -l drones */
    /* .kdrone 1440 -l drones */
    if ((argc == 3 && !strcasecmp(argv[1], "-l")) ||
        (argc == 4 && !strcasecmp(argv[2], "-l")))
    {
      if ((actionid = find_list(argv[argc - 1])) == -1)
      {
        send_to_connection(connection_p, "No such list.");
        return;
      }
      list = &client_lists[actionid];
      if (list->name[0] == '\0')
      {
        send_to_connection(connection_p, "No such list.");
        return;
      }
      DLINK_FOREACH(ptr, list->dlink.head)
      {
        user = ptr->data;
        if ((userhost = get_method_userhost(actionid, NULL, user->username,
                                            user->host)) == NULL)
        {
          send_to_connection(connection_p,
                             "Error in get_method_userhost().  Aborting...");
          continue;
        }

        if (argc == 3)
          send_to_server("KLINE %s :%s",
                         userhost, actions[actionid].reason);
        else
          send_to_server("KLINE %s %s :%s",
                         argv[1], userhost, actions[actionid].reason);
      }
    }
    /* .kdrone 1440 bill@ummm.E */
    /* .kdrone 1440 billy-jon */
    else
    {
      if((p = strchr(argv[2], '@')) != NULL)
      {
        *p++ = '\0';
        userhost = get_method_userhost(actionid, NULL, argv[2], p);
      }
      else
      {
        userhost = get_method_userhost(actionid, argv[2], NULL, NULL);
      }

      if (userhost == NULL)
      {
        send_to_connection(connection_p,
                           "Error in get_method_userhost().  Aborting...");
        return;
      }

      send_to_server("KLINE %s %s :%s", 
		     argv[1], userhost, actions[actionid].reason);
    }
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
    send_to_connection(connection_p, "Usage: %s <[mask]|[-c]>", argv[0]);
    return;
  }

  if (strcasecmp(argv[1], "-c") == 0)
  {
    memset((char *)&config_entries.testline_umask, 0,
           sizeof(config_entries.testline_umask));
    config_entries.testline_cnctn = NULL;
    send_to_connection(connection_p, "testline cleared");
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
  send_to_all(NULL, FLAGS_ALL, "%s is saving user preferences");
  save_umodes(connection_p->registered_nick);
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

void
m_dline(struct connection *connection_p, int argc, char *argv[])
{
  char *p, reason[MAX_BUFF];
  struct user_entry *user;
  dlink_node *ptr;
  int i, len;

  if (!(connection_p->type & FLAGS_DLINE))
  {
    send_to_connection(connection_p, "You do not have access to .dline");
    return;
  }
  if (config_entries.hybrid && !(tcm_status.oper_privs & PRIV_DLINE))
  {
    send_to_connection(connection_p, "We do not have access to DLINE on the server");
    return;
  }
  if ((argc < 2) || (strcasecmp(argv[1], "-l") == 0 && argc < 3))
  {
    send_to_connection(connection_p, "Usage: %s <[address]|[-l list]> [reason]",
                       argv[0]);
    return;
  }


  if (strcasecmp(argv[1], "-l") == 0)
  {
    if (argc >= 4)
    {
      p = reason;
      for (i = 3; i < argc; i++)
      {
        len = sprintf(p, "%s ", argv[i]);
        p += len;
      }
      /* blow away last ' ' */
      *--p = '\0';
    }
    else
      snprintf(reason, sizeof(reason), "No reason");

    if ((len = find_list(argv[2])) == -1)
    {
      send_to_connection(connection_p, "No such list.");
      return;
    }

    send_to_all(NULL, FLAGS_ALL, "*** dline -l %s :%s by %s",
                argv[2], reason, connection_p->registered_nick);
    if ((connection_p->type & FLAGS_INVS) == 0)
    {
      strncat(reason, " [", sizeof(reason)-strlen(reason));
      strncat(reason, connection_p->nick, sizeof(reason)-strlen(reason));
      strncat(reason, "]", sizeof(reason)-strlen(reason));
    }

    DLINK_FOREACH(ptr, client_lists[len].dlink.head)
    {
      user = ptr->data;
      log_kline("DLINE", user->ip_host, 0, connection_p->registered_nick,
                reason);
      send_to_server("DLINE %s :%s", user->ip_host, reason);
    }
  }
  else
  {
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
    }
    else
      snprintf(reason, sizeof(reason), "No reason");

    log_kline("DLINE", argv[1], 0, connection_p->registered_nick,
              reason);

    send_to_all(NULL, FLAGS_ALL, "*** dline %s :%s by %s", argv[1],
		reason, connection_p->registered_nick);

    if((connection_p->type & FLAGS_INVS) == 0)
    {
      strncat(reason, " [", sizeof(reason)-strlen(reason));
      strncat(reason, connection_p->nick,
              sizeof(reason)-strlen(reason));
      strncat(reason, "]", sizeof(reason)-strlen(reason));
    }
    send_to_server("DLINE %s :%s", argv[1], reason);
  }
}

void
m_undline(struct connection *connection_p, int argc, char *argv[])
{
  if (!(connection_p->type & FLAGS_DLINE))
  {
    send_to_connection(connection_p, "You do not have access to .undline");
    return;
  }
  if (config_entries.hybrid && !(tcm_status.oper_privs & PRIV_UNLNE))
  {
    send_to_connection(connection_p, "We do not have access to UNDLINE on the server");
    return;
  }

  send_to_all(NULL, FLAGS_ALL, "*** undline %s by %s", argv[1],
              connection_p->registered_nick);
  send_to_server("UNDLINE %s", argv[1]);
}


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
  char list[BUFFERSIZE], pattern[MAX_USER + MAX_HOST + 2], c;
  const char *usage;
  int regex = NO;

  list[0] = pattern[0] = c = '\0';
  optind = 1;

#ifdef HAVE_REGEX_H
  usage = "Usage: %s [-r] [-l list] <pattern>";

  while ((c = getopt(argc, argv, "l:r")) != -1)
#else
  usage = "Usage: %s [-r] [-l list] <pattern>";

  while ((c = getopt(argc, argv, "l:")) != -1)
#endif
  {
    switch (c)
    {
      case 'l':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(list, optarg, sizeof(list));
        break;

#ifdef HAVE_REGEX_H
      case 'r':
        regex = YES;
        break;
#endif

      case '?':
      default:
        break;
    }
  }

  if (argc == 1)   
  {
    send_to_connection(connection_p, usage, argv[0]);
    return;
  }

  strlcpy(pattern, argv[argc-1], sizeof(pattern));

  list_nicks(connection_p, pattern[0] ? pattern : NULL, regex, list[0] ? list : NULL);
} 

void
m_list(struct connection *connection_p, int argc, char *argv[])
{
  char list[BUFFERSIZE], pattern[MAX_USER + MAX_HOST + 2], c;
  const char *usage;
  int regex = NO;

  list[0] = pattern[0] = c = '\0';
  optind = 1;
#ifdef HAVE_REGEX_H
  usage = "Usage: %s [-l list] <[-r regex]|[wildcarded userhost]>";

  while ((c = getopt(argc, argv, "l:r")) != -1)
#else
  usage = "Usage: %s [-l list] <wildcarded userhost>";

  while ((c = getopt(argc, argv, "l:")) != -1)
#endif
  {
    switch (c)
    {
      case 'l':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(list, optarg, sizeof(list));
        break;

#ifdef HAVE_REGEX_H
      case 'r':
        regex = YES;
        break;
#endif

      case '?':
      default:
        break;
    }
  }

  if (argc == 1)   
  {
    send_to_connection(connection_p, usage, argv[0]);
    return;
  }

  strlcpy(pattern, argv[argc-1], sizeof(pattern));

  kill_or_list_users(connection_p, pattern[0] ? pattern : NULL,
                     regex, DUMP, list[0] ? list : NULL, NULL);

  return;
}

void
m_gecos(struct connection *connection_p, int argc, char *argv[])
{
  char list[BUFFERSIZE], pattern[MAX_USER + MAX_HOST + 2], c;
  const char *usage;
  int regex = NO;

  list[0] = pattern[0] = c = '\0';
  optind = 1;
#ifdef HAVE_REGEX_H 
  usage = "Usage: %s [-l list] <[-r regex]|[wildcarded gecos]>";

  while ((c = getopt(argc, argv, "l:r")) != -1)
#else             
  usage = "Usage: %s [-l list] <wildcarded gecos>";

  while ((c = getopt(argc, argv, "l:")) != -1)
#endif
  {                
    switch (c)    
    { 
      case 'l':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(list, optarg, sizeof(list));
        break;

#ifdef HAVE_REGEX_H
      case 'r':
        regex = YES;
        break;
#endif

      case '?':
      default:
        send_to_connection(connection_p, usage, argv[0]);
        return;
    }
  }

  if (argc == 1)   
  {
    send_to_connection(connection_p, usage, argv[0]);
    return;
  }

  strlcpy(pattern, argv[argc-1], sizeof(pattern));

  list_gecos(connection_p, pattern[0] ? pattern : NULL, regex, list[0] ? list : NULL);
}

/* DEPRECATED */
void
m_ulist(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];

  send_to_connection(connection_p, "%s is deprecated.  Use .list instead.", argv[0]);

#ifdef HAVE_REGEX_H
  if(!(argc >= 2) || !(argc <= 5) ||
     /* .ulist -l list -r [a-z]	*/
     (strcasecmp(argv[1], "-l") == 0 && argc >= 4 && strcasecmp(argv[3], "-r") == 0 && argc < 5) ||
     /* .ulist -l list ?*	*/
     (strcasecmp(argv[1], "-l") == 0 && argc >= 4 && strcasecmp(argv[3], "-r") != 0 && argc < 4) ||
     /* .ulist -r [a-z]		*/
     (strcasecmp(argv[1], "-l") != 0 && argc >= 2 && strcasecmp(argv[1], "-r") == 0 && argc < 3) ||
     /* .ulist ?*		*/
     (strcasecmp(argv[1], "-l") != 0 && argc >= 2 && strcasecmp(argv[1], "-r") != 0 && argc < 2) )
  {
    send_to_connection(connection_p,
                       "Usage: %s [-l list] <[wildcard username]|[-r regex]>",
                       argv[0]);
    return;
  }

  if(strcasecmp(argv[1], "-l") == 0)
  {
    if (argc < 5)
    {
      snprintf(buf, sizeof(buf), "%s@*", argv[3]);
      kill_or_list_users(connection_p, buf, NO, MAKE, argv[2], NULL);
    }
    else
    {
      snprintf(buf, sizeof(buf), "%s@*", argv[4]);
      kill_or_list_users(connection_p, buf, YES, MAKE, argv[2], NULL);
    }
  }
  else if(argc == 2)
  {
    snprintf(buf, sizeof(buf), "%s@*", argv[1]);
    kill_or_list_users(connection_p, buf, NO, DUMP, NULL, NULL);
  }
  else if(strcasecmp(argv[1], "-r") == 0)
  {
    snprintf(buf, sizeof(buf), "%s@*", argv[2]);
    kill_or_list_users(connection_p, buf, YES, DUMP, NULL, NULL);
  }
  else
  {
    send_to_connection(connection_p,
                       "Usage: %s [-l list] <[wildcard username]|[-r regex]>",
                       argv[0]);
    return;
  }
#else
  if(!(argc >= 2) || !(argc <= 4) ||
     /* .ulist -l list ?*	*/
     (strcasecmp(argv[1], "-l") == 0 && argc < 4) ||
     /* .ulist ?*		*/
     (strcasecmp(argv[1], "-l") != 0 && argc < 2) )
  {
    send_to_connection(&connection_p,
                      "Usage: %s [-l list] <wildcard username>",
                       argv[0]);
    return;
  }

  if (argc > 2)
  {
    snprintf(buf, sizeof(buf), "%s@*", argv[3]);
    kill_or_list_users(connection_p, buf, NO, MAKE, argv[2], NULL);
  }
  else
  {
    snprintf(buf, sizeof(buf), "%s@*", argv[1]);
    kill_or_list_users(connection_p, buf, NO, DUMP, NULL, NULL);
  }
#endif /* HAVE_REGEX_H */

}

/* DEPRECATED */
void
m_hlist(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];

  send_to_connection(connection_p, "%s is deprecated.  Use .list instead.", argv[0]);

#ifdef HAVE_REGEX_H
  if(!(argc >= 2) || !(argc <= 5) ||
     /* .hlist -l list -r [a-z] */
     (strcasecmp(argv[1], "-l") == 0 && argc >= 4 && strcasecmp(argv[3], "-r") == 0 && argc < 5) ||
     /* .hlist -l list ?*       */
     (strcasecmp(argv[1], "-l") == 0 && argc >= 4 && strcasecmp(argv[3], "-r") != 0 && argc < 4) ||
     /* .hlist -r [a-z]         */
     (strcasecmp(argv[1], "-l") != 0 && argc >= 2 && strcasecmp(argv[1], "-r") == 0 && argc < 3) ||
     /* .hlist ?*               */
     (strcasecmp(argv[1], "-l") != 0 && argc >= 2 && strcasecmp(argv[1], "-r") != 0 && argc < 2) )
  {
    send_to_connection(connection_p,
                       "Usage: %s [-l list] <[wildcard host]|[-r regex]>",
		       argv[0]);
    return;
  }

  if(strcasecmp(argv[1], "-l") == 0)
  {
    if (argc < 5)
    {
      snprintf(buf, sizeof(buf), "*@%s", argv[3]);
      kill_or_list_users(connection_p, buf, NO, MAKE, argv[2], NULL);
    }
    else
    {
      snprintf(buf, sizeof(buf), "*@%s", argv[4]);
      kill_or_list_users(connection_p, buf, YES, MAKE, argv[2], NULL);
    }
  }
  else if(argc == 2)
  {
    snprintf(buf, sizeof(buf), "*@%s", argv[1]);
    kill_or_list_users(connection_p, buf, NO, DUMP, NULL, NULL);
  }
  else if(strcasecmp(argv[1], "-r") == 0)
  {
    snprintf(buf, sizeof(buf), "*@%s", argv[2]);
    kill_or_list_users(connection_p, buf, YES, DUMP, NULL, NULL);
  }
  else
  {
    send_to_connection(connection_p,
                       "Usage: %s [-l list] <[wildcard host]|[-r regex]>",
                       argv[0]);
    return;
  }
#else
  if(!(argc >= 2) || !(argc <= 4) ||
     /* .hlist -l list ?*       */
     (strcasecmp(argv[1], "-l") == 0 && argc < 4) ||
     /* .hlist ?*               */
     (strcasecmp(argv[1], "-l") != 0 && argc < 2) )
  {
    send_to_connection(connection_p,
                       "Usage: %s [-l list] <wildcard host>",
                       argv[0]);
    return;
  }

  if (argc > 2)
  {
    snprintf(buf, sizeof(buf), "*@%s", argv[3]);
    kill_or_list_users(connection_p, buf, NO, MAKE, argv[2], NULL);
  }
  else
  {
    snprintf(buf, sizeof(buf), "*@%s", argv[1]);
    kill_or_list_users(connection_p, buf, NO, DUMP, NULL, NULL);
  }
#endif /* HAVE_REGEX_H */

}

static void
m_smartlist(struct connection *connection_p, int argc, char *argv[])
{
  char nickp[BUFFERSIZE],  userp[BUFFERSIZE], hostp[BUFFERSIZE],
         ipp[BUFFERSIZE], gecosp[BUFFERSIZE],  allp[BUFFERSIZE], c;
  char matchp[6]; /* nick + user + host + ip + gecos + \0 = 6 */
  char list[BUFFERSIZE];
  const char *usage;
  int regex;

  nickp[0] = userp[0] = hostp[0] = ipp[0] = gecosp[0] = allp[0] = matchp[0] = list[0] = c = '\0';
  regex = NO;
  optind = 1;

#ifdef HAVE_REGEX_H
  usage = "Usage: %s [-r] [-l list name] [-n nick pattern] [-u user pattern] [-h host pattern] [-i ip pattern] [-g gecos pattern] [-a nick!user@host|ip;gecos pattern] [-m matching pattern]";

  while ((c = getopt(argc, argv, "rn:u:h:i:g:a:m:")) != -1)
#else
  usage = "Usage: %s [-l list name] [-n nick pattern] [-u user pattern] [-h host pattern] [-i ip pattern] [-g gecos pattern] [-a nick!user@host|ip;gecos pattern] [-m matching pattern]";

  while ((c = getopt(argc, argv, "n:u:h:i:g:a:m:")) != -1)
#endif
  {
    switch (c)
    {
#ifdef HAVE_REGEX_H
      case 'r':
        regex = YES;
        break;
#endif

      case 'l':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(list, optarg, sizeof(list));
        break;

      case 'n':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(nickp, optarg, sizeof(nickp));
        break;

      case 'u':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(userp, optarg, sizeof(userp));
        break;

      case 'h':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(hostp, optarg, sizeof(hostp));
        break;

      case 'i':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(ipp, optarg, sizeof(ipp));
        break;

      case 'g':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(gecosp, optarg, sizeof(gecosp));
        break;

      case 'a':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(allp, optarg, sizeof(allp));
        break;

      case 'm':
        if (optarg == NULL)
        {
          send_to_connection(connection_p, usage, argv[0]);
          return;
        }

        strlcpy(matchp, optarg, sizeof(matchp));
        break;

      case '?':
      default:
        send_to_connection(connection_p, usage, argv[0]);
        return;
    }
  }

  if (argc < 2)
  {
    send_to_connection(connection_p, usage, argv[0]);
    return;
  }

  list_smart(connection_p, regex,
             nickp[0]  ? nickp  : NULL,
             userp[0]  ? userp  : NULL,
             hostp[0]  ? hostp  : NULL,
             ipp[0]    ? ipp    : NULL,
             gecosp[0] ? gecosp : NULL,
             allp[0]   ? allp   : NULL,
             matchp[0] ? matchp : NULL,
             list[0]   ? list   : NULL);
}

#ifdef DEBUGMODE
void
m_sysnotice(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];
  char *aargv[5] = { tcm_status.my_server, "NOTICE", tcm_status.my_nick, buf, NULL };
  int a;

  if (argc <= 1)
  {
    send_to_connection(connection_p, "Usage: %s <system notice>",
                       argv[0]);
    return;
  }

  buf[0] = '\0';

  for (a=1; a<argc; ++a)
  {
    strlcat(buf, argv[a], sizeof(buf)-strlen(buf));
    strlcat(buf, " ", sizeof(buf)-strlen(buf));
  }
  buf[strlen(buf)-1] = '\0';
  
  send_to_connection(connection_p, "Simulating \"%s\"", buf);
  on_server_notice(NULL, 4, aargv);
}
#endif

static void
m_xline(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];
  int a;

  if (!(connection_p->type & FLAGS_XLINE))
  {
    send_to_connection(connection_p, "You do not have access to .xline");
    return;
  }
  if (!config_entries.hybrid || !(tcm_status.oper_privs & PRIV_XLINE))
  {
    send_to_connection(connection_p, "Error: XLINE not possible");
    return;
  }

  if (argc <= 1)
  {
    send_to_connection(connection_p, "Usage: %s <gecos pattern> [reason]",
                       argv[0]);
    return;
  }

  buf[0] = '\0';

  for (a=2; a<argc; ++a)
  {
    strlcat(buf, argv[a], sizeof(buf)-strlen(buf));
    strlcat(buf, " ", sizeof(buf)-strlen(buf));
  }
  buf[strlen(buf)-1] = '\0';

  send_to_server("XLINE %s :%s", argv[1], buf);
}

static void
m_unxline(struct connection *connection_p, int argc, char *argv[])
{
  if (!(connection_p->type & FLAGS_XLINE))
  {
    send_to_connection(connection_p, "You do not have access to .unxline");
    return;
  }
  if (!config_entries.hybrid || !(tcm_status.oper_privs & PRIV_XLINE))
  {
    send_to_connection(connection_p, "Error: UNXLINE not possible");
    return;
  }

  if (argc <= 1)
  {
    send_to_connection(connection_p, "Usage: %s <gecos pattern>",
                       argv[0]);
    return;
  }

  send_to_server("UNXLINE %s", argv[1]);
}

static void
m_jupe(struct connection *connection_p, int argc, char *argv[])
{
  char buf[MAX_BUFF];
  int a;

  if (!(connection_p->type & FLAGS_JUPE))
  {
    send_to_connection(connection_p, "You do not have access to .jupe");
    return;
  }
  if (config_entries.hybrid == NO)
  {
    send_to_connection(connection_p, "Error: RESV not possible");
    return;
  }

  if (argc <= 1)
  {
    send_to_connection(connection_p, "Usage: %s <channel/nick> [reason]",
                       argv[0]);
    return;
  }

  buf[0] = '\0';

  for (a=2; a<argc; ++a)
  {
    strlcat(buf, argv[a], sizeof(buf)-strlen(buf));
    strlcat(buf, " ", sizeof(buf)-strlen(buf));
  }
  buf[strlen(buf)-1] = '\0';

  if (config_entries.hybrid_version >= 7)
    send_to_server("RESV %s :%s", argv[1], buf);
  else
  {
    if (argv[1][0] != '#')
    {
      send_to_connection(connection_p, "Error: hybrid-6 cannot jupe nicknames");
      return;
    }
    send_to_server("MODE %s +j", argv[1]);
  }
}

static void
m_unjupe(struct connection *connection_p, int argc, char *argv[])
{
  if (!(connection_p->type & FLAGS_JUPE))
  {
    send_to_connection(connection_p, "You do not have access to .unjupe");
    return;
  }
  if (config_entries.hybrid == NO)
  {
    send_to_connection(connection_p, "Error: UNRESV not possible");
    return;
  }

  if (argc <= 1)
  {
    send_to_connection(connection_p, "Usage: %s <channel/nick>",
                       argv[0]);
    return;
  }

  if (config_entries.hybrid_version >= 7)
    send_to_server("UNRESV %s", argv[1]);
  else
  {
    if (argv[1][0] != '#')
    {
      send_to_connection(connection_p, "Error: hybrid-6 cannot jupe nicknames");
      return;
    }
    send_to_server("MODE %s -j", argv[1]);
  }
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
struct dcc_command dline_msgtab = {
 "dline", NULL, {m_unregistered, m_dline, m_dline}
};
struct dcc_command undline_msgtab = {
 "undline", NULL, {m_unregistered, m_undline, m_undline}
};
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
struct dcc_command smartlist_msgtab = {
 "smartlist", NULL, {m_unregistered, m_smartlist, m_smartlist}
};
#ifdef DEBUGMODE
struct dcc_command sysnotice_msgtab = {
 "sysnotice", NULL, {m_unregistered, m_not_admin, m_sysnotice}
};
#endif
struct dcc_command xline_msgtab = {
 "xline", NULL, {m_unregistered, m_xline, m_xline}
};
struct dcc_command unxline_msgtab = {
 "unxline", NULL, {m_unregistered, m_unxline, m_unxline}
};
struct dcc_command jupe_msgtab = {
 "jupe", NULL, {m_unregistered, m_jupe, m_jupe}
};
struct dcc_command unjupe_msgtab = {
 "unjupe", NULL, {m_unregistered, m_unjupe, m_unjupe}
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
  add_dcc_handler(&dline_msgtab);
  add_dcc_handler(&undline_msgtab);
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
  add_dcc_handler(&smartlist_msgtab);
#ifdef DEBUGMODE
  add_dcc_handler(&sysnotice_msgtab);
#endif
  add_dcc_handler(&uptime_msgtab);
  add_dcc_handler(&xline_msgtab);
  add_dcc_handler(&unxline_msgtab);
  add_dcc_handler(&jupe_msgtab);
  add_dcc_handler(&unjupe_msgtab);
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
