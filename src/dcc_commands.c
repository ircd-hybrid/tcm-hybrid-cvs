/* $Id: dcc_commands.c,v 1.44 2002/05/03 22:49:46 einride Exp $ */

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
#include "serverif.h"
#include "logging.h"
#include "commands.h"
#include "stdcmds.h"
#include "modules.h"
#include "wild.h"
#include "match.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

char *_version="20012009";

static void set_actions(int sock, char *key, char *act, int duration, char *reason);
static void save_umodes(char *registered_nick, unsigned long type);
static void load_umodes(int connect_id);
static unsigned long find_user_umodes(char *nick);
static void set_umode(int connnum, char *flags, char *registered_nick);
static void show_user_umodes(int sock, char *registered_nick);
static void register_oper(int connnum, char *password, char *who_did_command);
static void list_opers(int sock);
static void list_connections(int sock);
static void list_exemptions(int sock);
static void handle_disconnect(int sock,char *param2,char *who_did_command);
static void handle_save(int sock,char *nick);
static void report_multi(int sock, int nclones);
static void report_multi_host(int sock, int nclones);
static void report_multi_user(int sock, int nclones);
static void report_multi_virtuals(int sock, int nclones);
static int  islegal_pass(int connect_id,char *password);
static void print_help(int sock,char *text);

void _modinit();
void _moddeinit();

extern struct connection connections[];
extern struct s_testline testlines;
extern char * get_method_names(int method);
extern int get_method_number(char * name);

void m_vlist(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    prnt(connections[connnum].socket, "Usage: %s <wildcarded/regexp ip>\n",
         argv[0]);
  else if (argc == 2)
    list_virtual_users(connections[connnum].socket, argv[1], NO);
  else
    list_virtual_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage %s <wildcarded ip>\n", argv[0]);
  else
    list_virtual_users(connections[connnum].socket, argv[1], NO);
#endif
}

void m_class(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage: %s <class name>\n", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], NO);
}

void m_classt(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage: %s <class name>\n", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], YES);
}

void m_killlist(int connnum, int argc, char *argv[])
{
  char reason[1024];
  int i;

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
  {
    prnt(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex userhost>\n", argv[0]);
    return;
  }
  if (argc >= 4)
  {
    if (argv[3][0] == ':')
      snprintf(reason, sizeof(reason), "%s", argv[3]+1);
    else
      snprintf(reason, sizeof(reason), "%s", argv[3]);
    for (i=4; i<argc; ++i)
    {
      strncat(reason, " ", sizeof(reason)-strlen(reason));
      strncat(reason, argv[i], sizeof(reason)-strlen(reason));
    }
  }
#else
  if (argc < 2)
  {
    prnt(connections[connnum].socket,
         "Usage: %s <wildcarded userhost>\n", argv[0]);
    return;
  }
  if (argc >= 3)
  {
    if (argv[2][0] == ':')
      snprintf(reason, sizeof(reason), "%s", argv[2]+1);
    else
      snprintf(reason, sizeof(reason), "%s", argv[2]);
    for (i=3; i<argc; ++i)
    {
      strncat(reason, " ", sizeof(reason)-strlen(reason));
      strncat(reason, argv[i], sizeof(reason)-strlen(reason));
    }
  }
  else
    snprintf(reason, sizeof(reason), "No reason");
#endif
  if (!(connections[connnum].type & (TYPE_INVS|TYPE_INVM)))
  {
    strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            sizeof(reason)-strlen(reason));
    strncat(reason, ")", sizeof(reason)-strlen(reason));
  }
#ifdef HAVE_REGEX_H
  if (strcasecmp(argv[1], "-r"))
  {
    sendtoalldcc(SEND_OPERS_ONLY, "*** killlist %s :%s by %s\n", argv[1],
                 reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[1], reason, NO);
  }
  else
  {
    sendtoalldcc(SEND_OPERS_ONLY, "*** killlist %s :%s by %s\n", argv[2],
                 reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[2], reason, YES);
  }
#else
  sendtoalldcc(SEND_OPERS_ONLY, "*** killlist %s :%s by %s\n", argv[1],
               reason, connections[connnum].registered_nick);
  kill_list_users(connections[connnum].socket, argv[1], reason, NO);
#endif
}

void m_kline(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  int i, kline_time;

  if (argc < 3)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]> [reason]\n", argv[0]);
  else
  {
    if ((kline_time = atoi(argv[1])))
    {
      if (argc >= 4)
      {
        snprintf(buff, sizeof(buff), "%s",
                 (argv[3][0] == ':') ? argv[3]+1 : argv[3]);
        for (i=4; i < argc; ++i)
        {
          strncat(buff, " ", sizeof(buff)-strlen(buff));
          strncat(buff, argv[i], sizeof(buff)-strlen(buff));
        }
      }
      else
        snprintf(buff, sizeof(buff), "No reason");
      do_a_kline("kline", kline_time, argv[2], buff, 
                 connections[connnum].registered_nick);
    }
    else
    {
      if (argc >= 3)
      {
        snprintf(buff, sizeof(buff), "%s",
                 (argv[2][0] == ':') ? argv[2]+1 : argv[2]);
        for (i=3; i < argc; ++i)
        {
          strncat(buff, " ", sizeof(buff)-strlen(buff));
          strncat(buff, argv[i], sizeof(buff)-strlen(buff));
        }
      }
      else
        snprintf(buff, sizeof(buff), "No reason");
      do_a_kline("kline", 0, argv[1], buff,
                 connections[connnum].registered_nick);
    }
  }
}

extern int act_clone;
void m_kclone(int connnum, int argc, char *argv[])
{
  int kline_time=0;

  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
  {
    if (!(kline_time = atoi(argv[1])))
      toserv("KLINE %s :%s\n", argv[1], actions[act_clone].reason);
    else
      toserv("KLINE %d %s :%s\n", kline_time, argv[2], actions[act_clone].reason);
  }
}

extern int act_flood;
void m_kflood(int connnum, int argc, char *argv[])
{
  int kline_time;

  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
  {
    if (!(kline_time=atoi(argv[1])))
      toserv("KLINE %s :%s\n", argv[1], actions[act_flood].reason);
    else
      toserv("KLINE %d %s :%s\n", kline_time, argv[2], actions[act_flood].reason);
  }
}

void m_kperm(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
    do_a_kline("kperm", 0, argv[1], REASON_KPERM, 
               connections[connnum].registered_nick);
}

extern int act_link;
void m_klink(int connnum, int argc, char *argv[])
{
  int kline_time;

  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
  {
    if (!(kline_time=atoi(argv[1])))
      toserv("KLINE %s :%s\n", argv[1], actions[act_link].reason);
    else
      toserv("KLINE %d %s :%s\n", kline_time, argv[2], actions[act_link].reason);
  }
}

extern int act_drone;
void m_kdrone(int connnum, int argc, char *argv[])
{
  int kline_time;

  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
  {
    if (!(kline_time=atoi(argv[1])))
      toserv("KLINE %s :%s\n", argv[1], actions[act_drone].reason);
    else
      toserv("KLINE %d %s :%s\n", kline_time, argv[2], actions[act_drone].reason);
  }
}

extern int act_bot;
void m_kbot(int connnum, int argc, char *argv[])
{
  int kline_time;

  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
  {
    if (!(kline_time=atoi(argv[1])))
      toserv("KLINE %s :%s\n", argv[1], actions[act_bot].reason);
    else
      toserv("KLINE %d %s :%s\n", kline_time, argv[2], actions[act_bot].reason);
  }
}

void m_kill(int connnum, int argc, char *argv[])
{
  char reason[1024];
  int i;

  if (argc < 2)
  {
    prnt(connections[connnum].socket,
         "Usage: %s <nick|user@host> [reason]\n", argv[0]);
    return;
  }
  else if (argc == 2)
    snprintf(reason, sizeof(reason), "No reason");
  else
  {
    snprintf(reason, sizeof(reason), "%s", 
             (argv[2][0] == ':') ? argv[2]+1 : argv[2]);
    for (i=3; i < argc; ++i)
    {
      strncat(reason, " ", sizeof(reason)-strlen(reason));
      strncat(reason, argv[i], sizeof(reason)-strlen(reason));
    }
  }
  sendtoalldcc(SEND_KLINE_NOTICES_ONLY, "*** kill %s :%s by %s\n",
               argv[1], reason, connections[connnum].registered_nick);
  log_kline("KILL", argv[1], 0, connections[connnum].registered_nick, reason);
  if (!(connections[connnum].type & (TYPE_INVS|TYPE_INVM)))
  {
    strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            sizeof(reason)-strlen(reason));
    strncat(reason, ")", sizeof(reason)-strlen(reason));
  }
  toserv("KILL %s :%s\n", argv[1], reason);
}

extern int act_spambot;
void m_kspam(int connnum, int argc, char *argv[])
{
  int kline_time;

  if (argc < 2)
    prnt(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>\n", argv[0]);
  else
  {
    if (!(kline_time=atoi(argv[1])))
      toserv("KLINE %s :%s\n", argv[1], actions[act_spambot].reason);
    else
      toserv("KLINE %d %s :%s\n", kline_time, argv[2], actions[act_spambot].reason);
  }
}    

void m_hmulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      prnt(connections[connnum].socket,
           "Using a threshold less than 3 is not recommended, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_host(connections[connnum].socket, t);
}

void m_umulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      prnt(connections[connnum].socket,
           "Using a threshold less than 3 is not recommended, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_user(connections[connnum].socket, t);
}

void m_register(int connnum, int argc, char *argv[])
{
  if (connections[connnum].type & TYPE_REGISTERED)
  {
    prnt(connections[connnum].socket, "You are already registered.\n");
    return;
  }
  if (argc != 2)
    prnt(connections[connnum].socket, "Usage: %s <password>\n", argv[0]);
  else
    register_oper(connnum, argv[1], connections[connnum].nick);
}

void m_opers(int connnum, int argc, char *argv[])
{
  list_opers(connections[connnum].socket);
}

void m_testline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    prnt(connections[connnum].socket, "Usage: %s <mask>\n", argv[0]);
    return;
  }
  if (strcasecmp(argv[1], testlines.umask) == 0)
  {
    prnt(connections[connnum].socket, "Already pending %s\n", argv[1]);
    return;
  }
  snprintf(testlines.umask, sizeof(testlines.umask), "%s", argv[1]);
  testlines.index = connnum;
  toserv("TESTLINE %s\n", argv[1]);
}

void m_action(int connnum, int argc, char *argv[])
{
  //  char *p, dccbuff[MAX_BUFF];
  int kline_time, i;
  char methods[MAX_BUFF], reason[MAX_BUFF];

  switch (argc)
  {
    /* .action */
    case 1:
      set_actions(connections[connnum].socket, NULL, NULL, 0, NULL);
      break;
    /* .action clone */
    /* .action *c* */
    case 2:
      set_actions(connections[connnum].socket, argv[1], NULL, 0, NULL);
      break;
    /* .action clone :Cloning is prohibited */
    /* .action clone kline */
    /* .action clone kline :Cloning */
    /* .action clone kline 1440 ircwarn dccwarn :Cloning is prohibited*/        
    default:
      /* Scan up to first ':' (extracting first found number if any)
	 and make two strings; methods & reason */
      kline_time = 0;
      methods[0] = 0;
      reason[0] = 0;
      for (i=2;i<argc;i++) {
	if (argv[i][0]==':') {
	  snprintf(reason, sizeof(reason), "%s ", argv[i]+1);
	  for (;i<argc;i++) {
	    strncat(reason, argv[i], sizeof(reason));
	    strncat(reason, " ", sizeof(reason));
	  }
	  break;
	}
	if ((!kline_time) && (atoi(argv[i])>0)) {
	  kline_time = atoi(argv[i]);
	} else {
	  strncat(methods, argv[i], sizeof(methods));
	  strncat(methods, " ", sizeof(methods));
	}
      }
      i = strlen(methods);
      if (i && (methods[i-1]==' '))
	methods[i-1] = 0;
      i = strlen(reason);
      if (i && (reason[i-1]==' '))
	reason[i-1] = 0;
      set_actions(connections[connnum].socket, argv[1], 
		  methods[0] ? methods : NULL, 
		  kline_time, 
		  reason[0] ? reason : NULL);
      break;
  }
}

void m_set(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    if (connections[connnum].set_modes & SET_PRIVMSG)
      prnt(connections[connnum].socket, "MESSAGES\n");
    else
      prnt(connections[connnum].socket, "NOMESSAGES\n");
    if (connections[connnum].set_modes & SET_NOTICES)
      prnt(connections[connnum].socket, "NOTICES\n");
    else
      prnt(connections[connnum].socket, "NONOTICES\n");
    return;
  }
  if ((strcasecmp(argv[1],"MESSAGES")) == 0)
  {
    connections[connnum].set_modes |= SET_PRIVMSG;
    prnt(connections[connnum].socket, "You will see privmsgs sent to tcm\n");
  }
  else if ((strcasecmp(argv[1],"NOMESSAGES")) == 0)
  {
    connections[connnum].set_modes &= ~SET_PRIVMSG;
    prnt(connections[connnum].socket,
         "You will not see privmsgs sent to tcm\n");
  }
  else if ((strcasecmp(argv[1],"NOTICES")) == 0)
  {
    connections[connnum].set_modes |= SET_NOTICES;
    prnt(connections[connnum].socket,
         "You will see selected server notices\n");
  }
  else if ((strcasecmp(argv[1],"NONOTICES")) == 0)
  {
    connections[connnum].set_modes &= ~SET_NOTICES;
      prnt(connections[connnum].socket, "You will not see server notices\n");
  }
  else
  {
    prnt(connections[connnum].socket, "Usage: .set [MESSAGES|NOMESSAGES]\n");
    prnt(connections[connnum].socket, "Usage: .set [NOTICES|NONOTICES]\n");
  }
}

void m_uptime(int connnum, int argc, char *argv[])
{
  report_uptime(connections[connnum].socket);
}

void m_exemptions(int connnum, int argc, char *argv[])
{
  list_exemptions(connections[connnum].socket);
}

#ifndef OPERS_ONLY
void m_ban(int connnum, int argc, char *argv[])
{
  int j;

  if (argc >= 2)
  {
    if (argv[1][0] == '+')
      ban_manipulate(connections[connnum].socket, '+', argv[1]+1);
    else
      ban_manipulate(connections[connnum].socket, '-', argv[1]+1);
  }
  else
  {
    prnt(connections[connnum].socket, "Current bans:\n");
    for (j=0; j < MAXBANS; ++j)
    {
      if (!banlist[j].host[0]) break;
      if (!banlist[j].user[0]) break;
      prnt(connections[connnum].socket, "%s@%s\n", banlist[j].user,
           banlist[j].host);
    }
  }
}
#endif

void m_umode(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    prnt(connections[connnum].socket, "Your current flags are: %s\n",
         type_show(connections[connnum].type));
    return;
  }
  if (argc >= 3)
  {
    if (!(connections[connnum].type & TYPE_ADMIN))
    {
      prnt(connections[connnum].socket, "You aren't an admin\n");
      return;
    }
    if ((argv[2][0] == '+') || (argv[2][0] == '-'))
      set_umode(connnum,argv[2],argv[1]);
    else
        prnt(connections[connnum].socket,
             ".umode [user flags] | [user] | [flags]\n");
  }
  else
  {
    if ((argv[1][0] == '+') || (argv[1][0] == '-'))
      set_umode(connnum, argv[1], NULL);
    else
    {
      if (!(connections[connnum].type & TYPE_ADMIN))
        {
          prnt(connections[connnum].socket, "You aren't an admin\n");
          return;
        }
      show_user_umodes(connections[connnum].socket,argv[1]);
    }
  }
}

void m_connections(int connnum, int argc, char *argv[])
{
  list_connections(connections[connnum].socket);
}

void m_disconnect(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage: %s <nick>\n", argv[0]);
  else
    handle_disconnect(connections[connnum].socket, argv[1],
                      connections[connnum].registered_nick);
}

void m_help(int connnum, int argc, char *argv[])
{
  print_help(connections[connnum].socket, argv[1]);
}

void m_motd(int connnum, int argc, char *argv[])
{
  print_motd(connections[connnum].socket);
}

void m_save(int connnum, int argc, char *argv[])
{
  handle_save(connections[connnum].socket, 
              connections[connnum].registered_nick);
}

void m_close(int connnum, int argc, char *argv[])
{
  struct common_function *temp;

  prnt(connections[connnum].socket, "Closing connection\n");
  for (temp=dcc_signoff;temp;temp=temp->next)
    temp->function(connnum, 0, NULL);
}

/* ParaGod smells like tunafish. */
void m_op(int connnum, int argc, char *argv[])
{
  if (argc != 2)
    prnt(connections[connnum].socket, "Usage: %s <nick>\n");
  else
    op(config_entries.defchannel, argv[1]);
}

void m_cycle(int connnum, int argc, char *argv[])
{
  leave(config_entries.defchannel);
  sendtoalldcc(SEND_OPERS_ONLY, "I'm cycling.  Be right back.\n");
  sleep(1);
  /* probably on a cycle, we'd want the tcm to set
   * the key as well...
   */
  toserv("JOIN %s %s\nMODE %s +ntk %s\n", config_entries.defchannel,
         config_entries.defchannel_key, config_entries.defchannel,
         config_entries.defchannel_key);
}

void m_die(int connnum, int argc, char *argv[])
{
  sendtoalldcc(SEND_ALL_USERS, "I've been ordered to quit irc, goodbye.");
  toserv("QUIT :Dead by request!\n");
  log("DIEd by oper %s\n", connections[connnum].registered_nick);
  exit(1);
}

void m_restart(int connnum, int argc, char *argv[])
{
  sendtoalldcc(SEND_ALL_USERS, "I've been ordered to restart.");
  toserv("QUIT :Restart by request!\n");
  log("RESTART by oper %s", connections[connnum].registered_nick);
  sleep(1);
  execv(SPATH, NULL);
}

void m_info(int connnum, int argc, char *argv[])
{
  prnt(connections[connnum].socket, "real server name [%s]\n",
       config_entries.rserver_name);
  if (config_entries.hybrid)
    prnt(connections[connnum].socket, "Hybrid server version %d\n",
         config_entries.hybrid_version);
  else
    prnt(connections[connnum].socket, "Non hybrid server\n");
}

void m_locops(int connnum, int argc, char *argv[])
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
      toserv("LOCOPS :(%s) %s\n", connections[connnum].nick, dccbuff+1);
    else
      toserv("LOCOPS :(%s) %s\n", connections[connnum].nick, dccbuff);
  }
  else
    prnt(connections[connnum].socket,
         "Really, it would help if you said something\n");
}

void m_unkline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage: %s <user@host>\n", argv[0]);
  else
  {
    log("UNKLINE %s attempted by oper %s", argv[1],
        connections[connnum].registered_nick);
    sendtoalldcc(SEND_OPERS_ONLY, "UNKLINE %s attempted by oper %s", 
                 argv[1], connections[connnum].registered_nick);
    toserv("UNKLINE %s\n",argv[1]);
  }
}

void m_vbots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]));
  else
    report_vbots(connections[connnum].socket, 3);
}

#ifndef NO_D_LINE_SUPPORT
void m_dline(int connnum, int argc, char *argv[])
{
  char *p, reason[MAX_BUFF];
  int i, len;

  if (!(connections[connnum].type & TYPE_DLINE))
  {
    prnt(connections[connnum].socket, "You do not have access to .dline\n");
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
    sendtoalldcc(SEND_OPERS_ONLY, "*** dline %s :%s by %s", argv[1],
                 reason, connections[connnum].registered_nick);
    if (!connections[connnum].type & (TYPE_INVS|TYPE_INVM))
    {
      strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
      strncat(reason, connections[connnum].nick,
              sizeof(reason)-strlen(reason));
      strncat(reason, ")", sizeof(reason)-strlen(reason));
    }
    toserv("DLINE %s :%s\n", argv[1], reason);
  }
}
#endif

#ifdef ENABLE_QUOTE
void m_quote(int connnum, int argc, char *argv[])
{
  char *p, dccbuff[MAX_BUFF];
  int i, len;

  if (argc < 2)
  {
    prnt(connections[connnum].socket, "Usage: %s <server message>\n", 
         argv[0]);
    return;
  }
  p = dccbuff;
  for (i = 1; i < argc; i++)
  {
    len = sprintf(p, "%s ", argv[i]);
    p += len;
  }
  /* blow away last ' ' */
  *--p = '\0';
  toserv("%s\n", dccbuff);
}
#endif

void m_mem(int connnum, int argc, char *argv[])
{
  report_mem(connections[connnum].socket);
}

void m_clones(int connnum, int argc, char *argv[])
{
  report_clones(connections[connnum].socket);
}

void m_nflood(int connnum, int argc, char *argv[])
{
  report_nick_flooders(connections[connnum].socket);
}

void m_rehash(int connnum, int argc, char *argv[])
{
  sendtoalldcc(SEND_ALL_USERS, "*** rehash requested by %s", 
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    toserv("STATS I\nSTATS Y\n");
  else
    toserv("STATS E\nSTATS F\nSTATS Y\n");

  initopers();
}

void m_trace(int connnum, int argc, char *argv[])
{
  sendtoalldcc(SEND_OPERS_ONLY, "Trace requested by %s",
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  inithash();
  toserv("STATS Y\n");
}

void m_failures(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_failures(connections[connnum].socket, 7);
  else if (atoi(argv[1]) < 1)
    prnt(connections[connnum].socket, "Usage: %s [min failures]\n", argv[0]);
  else
    report_failures(connections[connnum].socket, atoi(argv[1]));
}

void m_domains(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_domains(connections[connnum].socket, 5);
  else if (atoi(argv[1]) < 1)
    prnt(connections[connnum].socket, "Usage: %s [min users]\n", argv[0]);
  else
    report_domains(connections[connnum].socket, atoi(argv[1]));
}

void m_bots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi(connections[connnum].socket, 3);
}

void m_vmulti(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi_virtuals(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi_virtuals(connections[connnum].socket, 3);
}

void m_nfind(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    prnt(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regexp nick>\n", argv[0]);
  else if (argc == 2)
    list_nicks(connections[connnum].socket, argv[1], NO);
  else
    list_nicks(connections[connnum].socket, argv[2], YES);
#else
  if (argc <= 2)
    prnt(connections[connnum].socket, "Usage: %s <wildcarded nick>\n", argv[0]);
  else
    list_nicks(connections[connnum].socket, argv[1], NO);
#endif
} 

void m_list(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    prnt(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex userhost>\n", argv[0]);
  else if (argc == 2)
    list_users(connections[connnum].socket, argv[1], NO);
  else
    list_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage: %s <wildcarded userhost>\n",
         argv[0]);
  else
    list_users(connections[connnum].socket, argv[1], NO);
#endif
}

#ifdef WANT_ULIST
void m_ulist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    prnt(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex username>\n", argv[0]);
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
    prnt(connections[connnum].socket, "Usage: %s <wildcarded username>\n",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}
#endif

#ifdef WANT_HLIST
void m_hlist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    prnt(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex host>\n", argv[0]);
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
    prnt(connections[connnum].socket, "Usage: %s <wildcarded host>\n",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}
#endif

/*
** dccproc()
**   Handles processing of dcc chat commands
*/
void 
dccproc(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  char dccbuff[MAX_BUFF];
  char who_did_command[2*MAX_NICK];
  int len;
  int i;
  int opers_only = SEND_ALL_USERS; 	/* Is it an oper only message ? */
  char *buffer, *p;

  if (argv[0][0] == '.')
  {
    prnt(connections[connnum].socket, "Unknown command [%s]\n", argv[0]+1);
    return;
  }
  p = buff;
  for (i = 0; i < argc; i++)
  {
    len = sprintf(p, "%s ", argv[i]);
    p += len;
  }
  /* blow away last ' ' */
  *--p = '\0';

  buffer=buff;

  who_did_command[0] = '\0';

  if((buffer[0] == 'o' || buffer[0] == 'O') && buffer[1] == ':')
  {
    opers_only = SEND_OPERS_ONLY;
    snprintf(dccbuff,sizeof(dccbuff) - 1,"O:<%s@%s> %s",
             connections[connnum].nick, config_entries.dfltnick, buffer+2);
  }
  else
    snprintf(dccbuff,sizeof(dccbuff) - 1,"<%s@%s> %s",
             connections[connnum].nick, config_entries.dfltnick, buffer);

  if(connections[connnum].type & TYPE_PARTYLINE )
    sendtoalldcc(opers_only, "%s", dccbuff); /* Thanks Garfr, Talen */
  else
  {
    if(opers_only == SEND_OPERS_ONLY)
      sendtoalldcc(opers_only, "%s", dccbuff);
    else
      prnt(connections[connnum].socket,
           "You are not +p, not sending to chat line\n");
  }
  return;
}

/*
 * set_actions
 *
 * inputs	- 
 * output	- NONE
 * side effects -
 */

static void 
set_actions(int sock, char *key, char *methods, int duration, char *reason)
{
  int i;
  char * p;
  int newmethods = 0;
  int changing = (methods || duration || reason);

  while (methods) {
    p = strchr(methods, ' ');
    if (p) 
      *p++ = 0;
    // Lookup method constant based on method name
    i = get_method_number(methods);
    if (i) {
      newmethods |= i;
    } else {
      prnt(sock, "%s is not a valid method\n", methods);
      return;
    }
    methods = p;
  }

  if (key == NULL)
    key = "*";
  if (changing) {
    prnt(sock, "Updating actions matching '%s'\n", key);
  } else {
    prnt(sock, "Listing actions matching '%s'\n", key);
  }

  for (i=0; i<MAX_ACTIONS; i++) {
    if (actions[i].name[0]) {
      if (!wldcmp(key, actions[i].name)) {
	if (newmethods) 
	  set_action_method(i, newmethods);
	if (reason)
	  set_action_reason(i, reason);
	if (duration)
	  set_action_time(i, duration);
	
	if (changing) {
	  prnt(sock, "%s action now: %s, duration %d, reason '%s'\n", actions[i].name,
	       get_method_names(actions[i].method),
	       actions[i].klinetime,
	       actions[i].reason);
	} else {
	  prnt(sock, "%s action: %s, duration %d, reason '%s'\n", actions[i].name,
	       get_method_names(actions[i].method),
	       actions[i].klinetime,
	       actions[i].reason);
	}
      }
    }
  }
}

/*
 * set_umode
 *
 * inputs	- connection number
 * 		- flags as string
 * 		- nick to change, or NULL if self
 * output	- NONE
 * side effects	-
 */

static void 
set_umode(int connnum, char *flags, char *registered_nick)
{
  int i;
  int reversing = NO;
  int z;
  int found = NO;
  unsigned long type;
  unsigned long new_type;

  /* UMODE! -bill */
  
  if(!registered_nick)
  {
    for( i=0; flags[i]; i++ )
    {
      switch(flags[i])
      {
      case 'e': type = TYPE_ECHO; break;
      case 'i': type = TYPE_INVS; break;
      case 'k': type = TYPE_KLINE; break;
      case 'l': type = TYPE_LINK; break;
      case 'm': type = TYPE_MOTD; break;
      case 'o': type = TYPE_LOCOPS; break;
      case 'p': type = TYPE_PARTYLINE; break;
      case 's': type = TYPE_STAT; break;
      case 'w': type = TYPE_WARN; break;

      case 'I':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_INVM ;
	else
	  type = 0;
	break;

#ifndef NO_D_LINE_SUPPORT
      case 'D':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_DLINE ;
	else
	  type = 0;
	break;
#endif

      case 'G':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_GLINE ;
	else
	  type = 0;
	break;

#ifdef ENABLE_W_FLAG
      case 'W':
        if (connections[connnum].type & TYPE_ADMIN)
          type = TYPE_OPERWALL ;
        else
          type = 0;
#endif

      case '-':
	type = 0;
	reversing=YES;
	break;

      case '+':
	type = 0;
	reversing=NO;
	break;

      default:
	type = 0;
	break;
      }

      if (reversing)
	connections[connnum].type &= ~type;
      else
	connections[connnum].type |= type;
    }

    prnt(connections[connnum].socket,
	 "Your flags are now: +%s\n",
	 type_show(connections[connnum].type));

    save_umodes(connections[connnum].registered_nick,
		connections[connnum].type);
  }
  else /* only called if ADMIN */
  {
    for(z=0;z<MAXDCCCONNS;++z)
    {
      if(found)
	break;

      if (strcasecmp(registered_nick, connections[z].registered_nick) == 0)
      {
	found = YES;
	
	for(i=0; flags[i] ;i++)
	{
	  switch(flags[i])
	  {
#ifndef NO_D_LINE_SUPPORT
	  case 'D': type = TYPE_DLINE; break;
#endif
	  case 'G': type = TYPE_GLINE; break;
	  case 'I': type = TYPE_INVM; break;
	  case 'K': type = TYPE_REGISTERED; break;
	  case 'O': type = TYPE_OPER; break;
	  case 'S': type = TYPE_SUSPENDED; break;
#ifdef ENABLE_W_FLAG
          case 'W': type = TYPE_OPERWALL; break;
#endif
	  case 'e': type = TYPE_ECHO; break;
	  case 'i': type = TYPE_INVS; break;
	  case 'k': type = TYPE_KLINE; break;
	  case 'l': type = TYPE_LINK; break;
	  case 'm': type = TYPE_MOTD; break;
	  case 'o': type = TYPE_LOCOPS; break;
	  case 'p': type = TYPE_PARTYLINE; break;
	  case 's': type = TYPE_STAT; break;
	  case 'w': type = TYPE_WARN; break;
	  case '-':
	    reversing=YES;
	    type = 0;
	    break;
	  case '+':
	    reversing=NO;
	    type = 0;
	    break;
	  default:
	    type = 0;
	    break;
	  }

	  /* don't let an admin suspend an admin */
	  
	  if( (connections[z].type & TYPE_ADMIN) &&
	      (type&TYPE_SUSPENDED))
	    continue;

	  if(type)
	  {
	    if (!reversing)
	      connections[z].type |= type;
	    else
	      connections[z].type &= ~type;
	  }
	}

	prnt(connections[connnum].socket,
	     "Flags for %s are now: +%s\n",
	     registered_nick, type_show(connections[z].type));

	prnt(connections[z].socket,
	     "Flags for you changed by %s are now: +%s\n",
	     connections[connnum].nick,
	     type_show(connections[z].type));
      }
    }

    if(!found)
    {
      new_type=0;

      for(z=0;userlist[z].user[0];z++)
      {
	if(found)
	  break;

	if (strcasecmp(registered_nick, userlist[z].usernick) == 0)
	{
	  found = YES;

	  new_type = userlist[z].type;

	  /* default them to partyline */
	  new_type |= TYPE_PARTYLINE;

	  /* Only use user.pref if they exist */
	  if( (type = find_user_umodes(registered_nick)) )
	  {
	    new_type &= TYPE_ADMIN;
	    new_type |= type;
	    type = 0;
	  }

	  for(i=0; flags[i] ;i++)
	  {
	    switch(flags[i])
	    {
	    case 'I': type = TYPE_INVM; break;
	    case 'K': type = TYPE_REGISTERED; break;
	    case 'G': type = TYPE_GLINE; break;
#ifndef NO_D_LINE_SUPPORT
	    case 'D': type = TYPE_DLINE; break;
#endif
	    case 'O': type = TYPE_OPER; break;
	    case 'S': type = TYPE_SUSPENDED; break;
#ifdef ENABLE_W_FLAG
            case 'W': type = TYPE_OPERWALL; break;
#endif
	    case 'k': type = TYPE_KLINE; break;
	    case 'p': type = TYPE_PARTYLINE; break;
	    case 's': type = TYPE_STAT; break;
	    case 'w': type = TYPE_WARN; break;
	    case 'e': type = TYPE_ECHO; break;
	    case 'i': type = TYPE_INVS; break;
	    case 'l': type = TYPE_LINK; break;
	    case 'm': type = TYPE_MOTD; break;
	    case 'o': type = TYPE_LOCOPS; break;
	    case '-':
	      reversing=YES;
	      type = 0;
	      break;
	    case '+':
	      reversing=NO;
	      type = 0;
	      break;
	    default:
	      type = 0;
	      break;
	    }
		      
	    if( (new_type & TYPE_ADMIN) &&
		(type&TYPE_SUSPENDED))
	      continue;

	    if (!reversing)
	      new_type |= type;
	    else
	      new_type &= ~type;
	  }
	  
	  prnt(connections[connnum].socket,
	       "Startup flags for %s are now: +%s\n",
	       registered_nick, type_show(new_type));
	  save_umodes(registered_nick, new_type);
	}
      }
    }
  }
}

/*
 * save_umodes
 *
 * inputs	- registered nick
 *		- flags to save
 * output	- none
 * side effect	- 
 */

static void 
save_umodes(char *registered_nick, unsigned long type)
{
  FILE *fp;
  char user_pref[MAX_BUFF];

  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"w")) == NULL)
  {
    sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		 user_pref );
    return;
  }

  fprintf(fp,"%lu\n",
	  type & ~(TYPE_ADMIN|TYPE_PENDING));
  (void)fclose(fp);
}

/*
 * load_umodes
 *
 * input	- connection id 
 * output	- none
 * side effect	- 
 */

static void 
load_umodes(int connect_id)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  unsigned long type;

  (void)snprintf(user_pref,sizeof(user_pref) - 1,"etc/%s.pref",
                connections[connect_id].registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    if((fp = fopen(user_pref,"w")) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		   user_pref );
      return;
    }
    type = connections[connect_id].type;
    fprintf(fp,"%lu\n", type & ~(TYPE_ADMIN|TYPE_PENDING));
    (void)fclose(fp);
    return;
  }

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';
  
  sscanf(type_string,"%lu",&type);
  type &= ~(TYPE_ADMIN|TYPE_PENDING);

  connections[connect_id].type &= TYPE_ADMIN;
  connections[connect_id].type |= type;

  if( type & TYPE_SUSPENDED )
  {
    type = type & TYPE_SUSPENDED;
  }

  prnt(connections[connect_id].socket, "Set umodes from %s\n", user_pref );
  prnt(connections[connect_id].socket, "Your current flags are now: %s\n",
       type_show(connections[connect_id].type));
}

/*
 * find_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static unsigned long 
find_user_umodes(char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  int  unsigned long type;

  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if ((fp = fopen(user_pref,"r")) == NULL)
  {
    return 0L;
  }

  if ((fgets(type_string,30,fp)) == NULL)
  {
    (void)fclose(fp);
    return 0L;
  }

  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';

  sscanf(type_string,"%lu",&type);

  type &= ~(TYPE_ADMIN|TYPE_PENDING);

  return type;
}

/*
 * show_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static void 
show_user_umodes(int sock, char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  int  i;
  unsigned long type = 0;
  unsigned long pref_type;
  char *p;
  int  found = NO;

  for(i=0; userlist[i].user[0]; i++)
  {
    if (strcasecmp(registered_nick, userlist[i].usernick) == 0)
    {
      type = userlist[i].type;
      found = YES;
      break;
    }
  }

  if(!found)
  {
    prnt(sock,"Can't find user [%s]\n", registered_nick );
    return;
  }
     
  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    prnt(sock,"%s user flags are %s\n", 
	 registered_nick,
	 type_show(type));
    return;
  }

  type &= TYPE_ADMIN ;

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';

  sscanf(type_string,"%lu",&pref_type);

  pref_type &= ~(TYPE_ADMIN|TYPE_PENDING);

  prnt(sock,"%s user flags are %s\n", 
       registered_nick,
       type_show(type|pref_type));
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
  if (password)
  {
    if ( islegal_pass(connnum, password) )
    {
      load_umodes(connnum);
	  
      if ( connections[connnum].type & TYPE_SUSPENDED)
      {
	prnt(connections[connnum].socket,
	     "You are suspended\n");
	sendtoalldcc(SEND_OPERS_ONLY,"%s is suspended\n",
		     who_did_command);
	if (connections[connnum].type &
	    (TYPE_PENDING))
	  connections[connnum].type &= ~TYPE_PENDING;
      }
      else
      {
	prnt(connections[connnum].socket,
	     "You are now registered\n");
	sendtoalldcc(SEND_OPERS_ONLY,
		     "%s has registered\n",
		     who_did_command);
	if (connections[connnum].type &
	    (TYPE_PENDING))
	  connections[connnum].type &= ~TYPE_PENDING;
      }
    }
    else
    {
      prnt(connections[connnum].socket,"illegal password\n");
      sendtoalldcc(SEND_OPERS_ONLY,
		   "illegal password from %s\n",
		   who_did_command);
    }
  }
  else
  {
    prnt(connections[connnum].socket,"missing password\n");
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

    prnt(sock,
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
  int i;

  for (i=0; i<MAXHOSTS; i++)
  {
    if(hostlist[i].host[0] == 0)
      break;
    prnt(sock,"%s@%s\n", hostlist[i].user, hostlist[i].host);
  }
}

/*
 * list_connections
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- active connections are listed to socket
 */

static void 
list_connections(int sock)
{
  int i;

  for (i=1; i<maxconns; i++)
  {
    if (connections[i].socket != INVALID)
    {
      if(connections[i].registered_nick[0] != 0)
      {
	prnt(sock,
	     "%s/%s %s (%s@%s) is connected - idle: %ld\n",
	     connections[i].nick,
	     connections[i].registered_nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time );
      }
      else
      {
	prnt(sock,
	     "%s %s (%s@%s) is connected - idle: %ld\n",
	     connections[i].nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time  );
      }
    }
  }
}

/*
 * handle_disconnect
 *
 * inputs	- socket
 *		- who did the command
 * output	- NONE
 * side effects	- disconnect user
 */

static void 
handle_disconnect(int sock,char *nickname,char *who_did_command)
{
  char *type;
  int  i;
  struct common_function *temp;

  if (nickname == NULL)
    prnt(sock, "Usage: disconnect <nickname>\n");
  else
  {
    for (i=1; i<maxconns; i++)
      if (sock != INVALID && strcasecmp(nickname,connections[i].nick) == 0)
      {
	type = "user";
	if(connections[i].type & TYPE_OPER)
	  type = "oper";

	prnt(sock,
	     "Disconnecting %s %s\n",
	     type,
	     connections[i].nick);
	prnt(sock,
	     "You have been disconnected by oper %s\n",
	     who_did_command);
	for (temp=dcc_signoff;temp;temp=temp->next)
	  temp->function(i, 0, NULL);
      }
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
  prnt(sock, "Saving %s file\n", CONFIG_FILE);
  sendtoalldcc(SEND_OPERS_ONLY, "%s is saving %s\n", nick, CONFIG_FILE);
  save_prefs();
}

#ifdef IRCD_HYBRID
/*
 * ircd-hybrid-7 loadable module code goes here
 */
#else
struct TcmMessage vlist_msgtab = {
 ".vlist", 0, 0,
 {m_unregistered, m_not_oper, m_vlist, m_vlist}
};
struct TcmMessage class_msgtab = {
 ".class", 0, 0,
 {m_unregistered, m_not_oper, m_class, m_class}
};
struct TcmMessage classt_msgtab = {
 ".classt", 0, 0,
 {m_unregistered, m_not_oper, m_classt, m_classt}
};
struct TcmMessage killlist_msgtab = {
 ".killlist", 0, 0,
 {m_unregistered, m_not_oper, m_killlist, m_killlist}
};
struct TcmMessage kline_msgtab = {
 ".kline", 0, 0,
 {m_unregistered, m_not_oper, m_kline, m_kline}
};
struct TcmMessage kclone_msgtab = {
 ".kclone", 0, 0,
 {m_unregistered, m_not_oper, m_kclone, m_kclone}
};
struct TcmMessage kflood_msgtab = {
 ".kflood", 0, 0,
 {m_unregistered, m_not_oper, m_kflood, m_kflood}
};
struct TcmMessage kperm_msgtab = {
 ".kperm", 0, 0,
 {m_unregistered, m_not_oper, m_kperm, m_kperm}
};
struct TcmMessage klink_msgtab = {
 ".klink", 0, 0,
 {m_unregistered, m_not_oper, m_klink, m_klink}
};
struct TcmMessage kdrone_msgtab = {
 ".kdrone", 0, 0,
 {m_unregistered, m_not_oper, m_kdrone, m_kdrone}
};
struct TcmMessage kbot_msgtab = {
 ".kbot", 0, 0,
 {m_unregistered, m_not_oper, m_kbot, m_kbot}
};
struct TcmMessage kill_msgtab = {
 ".kill", 0, 0,
 {m_unregistered, m_not_oper, m_kill, m_kill}
};
struct TcmMessage kspam_msgtab = {
 ".kspam", 0, 0,
 {m_unregistered, m_not_oper, m_kspam, m_kspam}
};
struct TcmMessage hmulti_msgtab = {
 ".hmulti", 0, 0,
 {m_unregistered, m_not_oper, m_hmulti, m_hmulti}
};
struct TcmMessage umulti_msgtab = {
 ".umulti", 0, 0,
 {m_unregistered, m_not_oper, m_umulti, m_umulti}
};
struct TcmMessage register_msgtab = {
 ".register", 0, 0,
 {m_register, m_not_oper, m_register, m_register}
};
struct TcmMessage opers_msgtab = {
 ".opers", 0, 0,
 {m_unregistered, m_not_oper, m_opers, m_opers}
};
struct TcmMessage testline_msgtab = {
 ".testline", 0, 0,
 {m_unregistered, m_not_oper, m_testline, m_testline}
};
struct TcmMessage action_msgtab = {
 ".action", 0, 0,
 {m_unregistered, m_not_oper, m_action, m_action}
};
struct TcmMessage set_msgtab = {
 ".set", 0, 0,
 {m_unregistered, m_not_oper, m_set, m_set}
};
struct TcmMessage uptime_msgtab = {
 ".uptime", 0, 0,
 {m_uptime, m_uptime, m_uptime, m_uptime}
};
struct TcmMessage exemptions_msgtab = {
 ".exemptions", 0, 0,
 {m_unregistered, m_not_oper, m_exemptions, m_exemptions}
};
#ifndef OPERS_ONLY
struct TcmMessage ban_msgtab = {
 ".ban", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_ban}
};
#endif
struct TcmMessage umode_msgtab = {
 ".umode", 0, 0,
 {m_unregistered, m_not_oper, m_umode, m_umode}
};
struct TcmMessage connections_msgtab = {
 ".connections", 0, 0,
 {m_connections, m_connections, m_connections, m_connections}
};
struct TcmMessage whom_msgtab = {
 ".whom", 0, 0,
 {m_connections, m_connections, m_connections, m_connections}
};
struct TcmMessage who_msgtab = {
 ".who", 0, 0,
 {m_connections, m_connections, m_connections, m_connections}
};
struct TcmMessage disconnect_msgtab = {
 ".disconnect", 0, 0,
 {m_disconnect, m_disconnect, m_disconnect, m_disconnect}
};
struct TcmMessage quit_msgtab = {
 ".quit", 0, 0,
 {m_disconnect, m_disconnect, m_disconnect, m_disconnect}
};
struct TcmMessage help_msgtab = {
 ".help", 0, 0,
 {m_help, m_not_oper, m_help, m_help}
};
struct TcmMessage motd_msgtab = {
 ".motd", 0, 0,
 {m_motd, m_not_oper, m_motd, m_motd}
};
struct TcmMessage save_msgtab = {
 ".save", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_save}
};
struct TcmMessage close_msgtab = {
 ".close", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_close}
};
struct TcmMessage op_msgtab = {
 ".op", 0, 0,
 {m_unregistered, m_not_oper, m_op, m_op}
};
struct TcmMessage cycle_msgtab = {
 ".cycle", 0, 0,
 {m_unregistered, m_not_oper, m_cycle, m_cycle}
};
struct TcmMessage die_msgtab = {
 ".die", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_die}
};
struct TcmMessage restart_msgtab = {
 ".restart", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_restart}
};
struct TcmMessage info_msgtab = {
 ".info", 0, 0,
 {m_info, m_not_oper, m_info, m_info}
};
struct TcmMessage locops_msgtab = {
 ".locops", 0, 0,
 {m_unregistered, m_not_oper, m_locops, m_locops}
};
struct TcmMessage unkline_msgtab = {
 ".unkline", 0, 0,
 {m_unregistered, m_not_oper, m_unkline, m_unkline}
};
struct TcmMessage vbots_msgtab = {
 ".vbots", 0, 0,
 {m_unregistered, m_not_oper, m_vbots, m_vbots}
};
#ifndef NO_D_LINE_SUPPORT
struct TcmMessage dline_msgtab = {
 ".dline", 0, 0,
 {m_unregistered, m_not_oper, m_dline, m_dline}
};
#endif
#ifdef ENABLE_QUOTE
struct TcmMessage quote_msgtab = {
 ".quote", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_quote}
};
#endif
struct TcmMessage mem_msgtab = {
 ".mem", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_mem}
};
struct TcmMessage clones_msgtab = {
 ".clones", 0, 0,
 {m_unregistered, m_not_oper, m_clones, m_clones}
};
struct TcmMessage nflood_msgtab = {
 ".nflood", 0, 0,
 {m_unregistered, m_not_oper, m_nflood, m_nflood}
};
struct TcmMessage rehash_msgtab = {
 ".rehash", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_rehash}
};
struct TcmMessage trace_msgtab = {
 ".trace", 0, 0,
 {m_unregistered, m_not_oper, m_trace, m_trace}
};
struct TcmMessage failures_msgtab = {
 ".failures", 0, 0,
 {m_unregistered, m_not_oper, m_failures, m_failures}
};
struct TcmMessage domains_msgtab = {
 ".domains", 0, 1,
 {m_unregistered, m_not_oper, m_domains, m_domains}
};
struct TcmMessage bots_msgtab = {
 ".bots", 0, 1,
 {m_unregistered, m_not_oper, m_bots, m_bots}
};
struct TcmMessage vmulti_msgtab = {
 ".vmulti", 0, 1,
 {m_unregistered, m_not_oper, m_vmulti, m_vmulti}
};
struct TcmMessage nfind_msgtab = {
 ".nfind", 0, 1,
 {m_unregistered, m_not_oper, m_nfind, m_nfind}
};
struct TcmMessage list_msgtab = {
 ".list", 0, 1,
 {m_unregistered, m_not_oper, m_list, m_list}
};
#ifdef WANT_ULIST
struct TcmMessage ulist_msgtab = {
 ".ulist", 0, 1,
 {m_unregistered, m_not_oper, m_ulist, m_ulist}
};
#endif
#ifdef WANT_HLIST
struct TcmMessage hlist_msgtab = {
 ".hlist", 0, 1,
 {m_unregistered, m_not_oper, m_hlist, m_hlist}
};
#endif
#endif

void 
_modinit()
{
  add_common_function(F_DCC, dccproc);
  mod_add_cmd(&vlist_msgtab);
  mod_add_cmd(&class_msgtab);
  mod_add_cmd(&classt_msgtab);
  mod_add_cmd(&killlist_msgtab);
  mod_add_cmd(&kline_msgtab);
  mod_add_cmd(&kclone_msgtab);
  mod_add_cmd(&kflood_msgtab);
  mod_add_cmd(&kperm_msgtab);
  mod_add_cmd(&klink_msgtab);
  mod_add_cmd(&kdrone_msgtab);
  mod_add_cmd(&kbot_msgtab);
  mod_add_cmd(&kill_msgtab);
  mod_add_cmd(&kspam_msgtab);
  mod_add_cmd(&hmulti_msgtab);
  mod_add_cmd(&umulti_msgtab);
  mod_add_cmd(&register_msgtab);
  mod_add_cmd(&opers_msgtab);
  mod_add_cmd(&testline_msgtab);
  mod_add_cmd(&action_msgtab);
  mod_add_cmd(&set_msgtab);
  mod_add_cmd(&exemptions_msgtab);
#ifndef OPERS_ONLY
  mod_add_cmd(&ban_msgtab);
#endif
  mod_add_cmd(&umode_msgtab);
  mod_add_cmd(&connections_msgtab);
  mod_add_cmd(&whom_msgtab);
  mod_add_cmd(&who_msgtab);
  mod_add_cmd(&disconnect_msgtab);
  mod_add_cmd(&quit_msgtab);
  mod_add_cmd(&help_msgtab);
  mod_add_cmd(&motd_msgtab);
  mod_add_cmd(&save_msgtab);
  mod_add_cmd(&close_msgtab);
  mod_add_cmd(&op_msgtab);
  mod_add_cmd(&cycle_msgtab);
  mod_add_cmd(&die_msgtab);
  mod_add_cmd(&restart_msgtab);
  mod_add_cmd(&info_msgtab);
  mod_add_cmd(&locops_msgtab);
  mod_add_cmd(&unkline_msgtab);
  mod_add_cmd(&vbots_msgtab);
#ifndef NO_D_LINE_SUPPORT
  mod_add_cmd(&dline_msgtab);
#endif
#ifdef ENABLE_QUOTE
  mod_add_cmd(&quote_msgtab);
#endif
  mod_add_cmd(&mem_msgtab);
  mod_add_cmd(&clones_msgtab);
  mod_add_cmd(&nflood_msgtab);
  mod_add_cmd(&rehash_msgtab);
  mod_add_cmd(&trace_msgtab);
  mod_add_cmd(&failures_msgtab);
  mod_add_cmd(&domains_msgtab);
  mod_add_cmd(&bots_msgtab);
  mod_add_cmd(&vmulti_msgtab);
  mod_add_cmd(&nfind_msgtab);
  mod_add_cmd(&list_msgtab);
#ifdef WANT_ULIST
  mod_add_cmd(&ulist_msgtab);
#endif
#ifdef WANT_HLIST
  mod_add_cmd(&hlist_msgtab);
#endif
  mod_add_cmd(&uptime_msgtab);
}

void
_moddeinit()
{
  mod_del_cmd(&uptime_msgtab);
  mod_del_cmd(&mem_msgtab);
  mod_del_cmd(&clones_msgtab);
  mod_del_cmd(&nflood_msgtab);
  mod_del_cmd(&rehash_msgtab);
  mod_del_cmd(&trace_msgtab);
  mod_del_cmd(&failures_msgtab);
  mod_del_cmd(&domains_msgtab);
  mod_del_cmd(&bots_msgtab);
  mod_del_cmd(&vmulti_msgtab);
  mod_del_cmd(&nfind_msgtab);
  mod_del_cmd(&list_msgtab);
#ifdef WANT_ULIST
  mod_del_cmd(&ulist_msgtab);
#endif
#ifdef WANT_HLIST
  mod_del_cmd(&hlist_msgtab);
#endif
}

/*
 * report_multi_host()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

static void report_multi_host(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int foundany = NO;

  nclones-=1;
  for (i = 0; i < HASHTABLESIZE; ++i)
    {
      for (top = userptr = hosttable[i]; userptr; userptr = userptr->collision)
        {
          /* Ensure we haven't already checked this user & domain */

          for( temp = top, numfound = 0; temp != userptr;
               temp = temp->collision)
            {
              if (!strcmp(temp->info->host,userptr->info->host))
                break;
            }

          if (temp == userptr)
            {
              for ( temp = userptr; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->host,userptr->info->host))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      prnt(sock,
                           "Multiple clients from the following userhosts:\n");
                    }

                  prnt(sock,
                       " %s %2d connections -- *@%s {%s}\n",
                       (numfound-nclones > 2) ? "==>" : "   ",
                       numfound,
                       userptr->info->host,
                       userptr->info->class);
                }
            }

        }
    }
  if (!foundany)
    prnt(sock, "No multiple logins found.\n");
}

/*
 * report_multi()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

static void
report_multi(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int notip;
  int foundany = NO;

  nclones-=2;  /* maybe someday i'll figure out why this is nessecary */
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( top = userptr = domaintable[i]; userptr;
           userptr = userptr->collision )
        {
          /* Ensure we haven't already checked this user & domain */
          for( temp = top, numfound = 0; temp != userptr;
               temp = temp->collision )
            {
              if (!strcmp(temp->info->user,userptr->info->user) &&
                  !strcmp(temp->info->domain,userptr->info->domain))
                break;
            }

          if (temp == userptr)
            {
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->user,userptr->info->user) &&
                      !strcmp(temp->info->domain,userptr->info->domain))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      prnt(sock,
                           "Multiple clients from the following userhosts:\n");
                    }
                  notip = strncmp(userptr->info->domain,userptr->info->host,
                                  strlen(userptr->info->domain)) ||
                    (strlen(userptr->info->domain) ==
                     strlen(userptr->info->host));
                  numfound++;   /* - zaph and next line*/
                  prnt(sock,
                       " %s %2d connections -- %s@%s%s {%s}\n",
                       (numfound-nclones > 2) ? "==>" :
                       "   ",numfound,userptr->info->user,
                       notip ? "*." : userptr->info->domain,
                       notip ? userptr->info->domain : ".*",
                       userptr->info->class);
                }
            }
        }
    }
  if (!foundany)
    prnt(sock, "No multiple logins found.\n");
}

/*
 * report_multi_user()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

static void
report_multi_user(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound;
  int i;
  int foundany = NO;

  nclones-=1;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( top = userptr = usertable[i]; userptr;
           userptr = userptr->collision )
        {
          numfound = 0;
          /* Ensure we haven't already checked this user & domain */

          for( temp = top; temp != userptr; temp = temp->collision )
            {
              if (!strcmp(temp->info->user,userptr->info->user))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;       /* fixed minor boo boo -bill */
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->user,userptr->info->user))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      prnt(sock,
                           "Multiple clients from the following usernames:\n");
                      foundany = YES;
                    }

                  prnt(sock,
                       " %s %2d connections -- %s@* {%s}\n",
                       (numfound-nclones > 2) ? "==>" : "   ",
                       numfound,userptr->info->user,
                       userptr->info->class);
                }
            }
        }
    }

  if (!foundany)
    {
      prnt(sock, "No multiple logins found.\n");
    }
}

/*
 * report_multi_virtuals()
 *
 * inputs       - socket to print out
 *              - number to consider as clone
 * output       - NONE
 * side effects -
 */

static void
report_multi_virtuals(int sock,int nclones)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int numfound;
  int i;
  int foundany = 0;

  if(!nclones)
    nclones = 5;

  nclones-=1;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for ( top = userptr = iptable[i]; userptr; userptr = userptr->collision )
        {
          numfound = 0;

          for (temp = top; temp != userptr; temp = temp->collision)
            {
              if (!strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->ip_class_c,
                              userptr->info->ip_class_c))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if (numfound > nclones)
                {
                  if (!foundany)
                    {
                      prnt(sock,
                           "Multiple clients from the following ip blocks:\n");
                      foundany = YES;
                    }

                  prnt(sock,
                       " %s %2d connections -- %s.*\n",
                       (numfound-nclones > 3) ? "==>" : "   ",
                       numfound,
                       userptr->info->ip_class_c);
                }
            }
        }
    }

  if (!foundany)
    prnt(sock, "No multiple virtual logins found.\n");
}

/*
 * islegal_pass()
 *
 * inputs       - user
 *              - host
 *              - password
 *              - int connect id
 * output       - YES if legal NO if not
 * side effects - NONE
 */

static int islegal_pass(int connect_id,char *password)
{
  int i;

  for(i=0;userlist[i].user && userlist[i].user[0];i++)
    {
      if ((!match(userlist[i].user,connections[connect_id].user)) &&
          (!wldcmp(userlist[i].host,connections[connect_id].host)))
        {
          if(userlist[i].password)
            {
#ifdef USE_CRYPT
              if(!strcmp((char*)crypt(password,userlist[i].password),
                         userlist[i].password))
                {
                  strncpy(connections[connect_id].registered_nick,
                          userlist[i].usernick,
                          MAX_NICK);
                  connections[connect_id].type = userlist[i].type;
                  return userlist[i].type;
                }
              else
                return 0;
#else
              if(!strcmp(userlist[i].password,password))
                {
                  strncpy(connections[connect_id].registered_nick,
                          userlist[i].usernick,
                          MAX_NICK);
                  connections[connect_id].type = userlist[i].type;
                  return(userlist[i].type);
                }
              else
                return(0);
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

  if(!text || (*text == '\0'))
    {
      if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
        {
          prnt(sock,"Help is not currently available\n");
          return;
        }
    }
  else
    {
      while(*text == ' ')
        text++;

      if (*text == '\0')
        {
          if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
            {
              prnt(sock,"Help is not currently available\n");
              return;
            }
        }

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( (userfile = fopen(help_file,"r")) == NULL)
        {
          prnt(sock,"Help for '%s' is not currently available\n",text);
          return;
        }
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      prnt(sock, "%s", line);
    }
  fclose(userfile);
}
