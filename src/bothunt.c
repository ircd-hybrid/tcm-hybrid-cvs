/* bothunt.c
 *
 * $Id: bothunt.c,v 1.195 2002/08/10 21:08:11 bill Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>

#include "setup.h"
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "stdcmds.h"
#include "parse.h"
#include "bothunt.h"
#include "userlist.h"
#include "logging.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"
#include "modules.h"
#include "tcm_io.h"
#include "parse.h"
#include "wingate.h"
#include "actions.h"
#include "match.h"
#include "handler.h"
#include "hash.h"

#ifdef HAVE_REGEX_H
#include <regex.h>
#define REGCOMP_FLAGS REG_EXTENDED
#define REGEXEC_FLAGS 0
#endif

static void check_nick_flood(char *snotice);
static void cs_clones(char *snotice);
static void link_look_notice(char *snotice);
static void connect_flood_notice(char *snotice, char *reason);
static void add_to_nick_change_table(char *user, char *host, char *last_nick);
static void stats_notice(char *snotice);
static void chopuh(int istrace,char *nickuserhost,struct user_entry *userinfo);
#define IS_FROM_TRACE		YES
#define IS_NOT_FROM_TRACE	NO

struct serv_command servnotice_msgtab = {
  "NOTICE", NULL, on_server_notice
};

/* Nick change flood detect */
struct nick_change_entry
{
  char user[MAX_USER];
  char host[MAX_HOST];
  char last_nick[MAX_NICK];
  int  nick_change_count;
  time_t first_nick_change;
  time_t last_nick_change;
  int noticed;
};
static struct nick_change_entry nick_changes[NICK_CHANGE_TABLE_SIZE];

/* Link look flood detect */
#define LINK_LOOK_TABLE_SIZE 10
struct link_look_entry
{
  char user[MAX_USER];
  char host[MAX_HOST];
  int  link_look_count;
  time_t last_link_look;
};
static struct link_look_entry link_look[LINK_LOOK_TABLE_SIZE];

/* Connect flood detect */
#define CONNECT_FLOOD_TABLE_SIZE 30
struct connect_flood_entry
{
  char user[MAX_USER];
  char host[MAX_HOST];
  char ip[MAX_IP];
  int  connect_count;
  time_t last_connect;
};
static struct connect_flood_entry connect_flood[CONNECT_FLOOD_TABLE_SIZE];

struct reconnect_clone_entry reconnect_clone[RECONNECT_CLONE_TABLE_SIZE];

struct msg_to_action
{
  char *msg_to_mon;
  int  len;
  int  action;
};

struct msg_to_action msgs_to_mon[] = {
  {MSG_CLIENT_CONNECTING, sizeof(MSG_CLIENT_CONNECTING)-1, CONNECT},
  {MSG_CLIENT_EXITING, sizeof(MSG_CLIENT_EXITING)-1, EXITING},
  {MSG_UNAUTHORIZED, sizeof(MSG_UNAUTHORIZED)-1, UNAUTHORIZED},
  {MSG_UNAUTHORISED, sizeof(MSG_UNAUTHORISED)-1, UNAUTHORIZED},
  {MSG_NICK_CHANGE, sizeof(MSG_NICK_CHANGE)-1, NICKCHANGE},
  {MSG_IDLE_TIME, sizeof(MSG_IDLE_TIME)-1, IGNORE},
  {MSG_LINKS, sizeof(MSG_LINKS)-1, LINK_LOOK},
  {MSG_KLINE, sizeof(MSG_KLINE)-1, IGNORE},  
  {MSG_STATS, sizeof(MSG_STATS)-1, STATS},
  {MSG_GOT_SIGNAL, sizeof(MSG_GOT_SIGNAL)-1, SIGNAL},
  {MSG_LINK_WITH, sizeof(MSG_LINK_WITH)-1, LINKWITH},
  {MSG_NICK_COLLISION, sizeof(MSG_NICK_COLLISION)-1, IGNORE},
  {MSG_SEND_MESSAGE, sizeof(MSG_SEND_MESSAGE)-1, IGNORE},
  {MSG_GHOSTED, sizeof(MSG_GHOSTED)-1, IGNORE},
  {MSG_CONNECT_FAILURE, sizeof(MSG_CONNECT_FAILURE)-1, IGNORE},
  {MSG_INVISIBLE_CLIENT, sizeof(MSG_INVISIBLE_CLIENT)-1, IGNORE},
  {MSG_OPER_COUNT_OFF, sizeof(MSG_OPER_COUNT_OFF)-1, IGNORE},
  {MSG_USER_COUNT_OFF, sizeof(MSG_USER_COUNT_OFF)-1, IGNORE},
  {MSG_SQUIT, sizeof(MSG_SQUIT)-1, SQUITOF},
  {MSG_MOTD, sizeof(MSG_MOTD)-1, MOTDREQ},
  {MSG_FLOODER, sizeof(MSG_FLOODER)-1, FLOODER},
  {MSG_USER, sizeof(MSG_USER)-1, SPAMBOT},
  {MSG_I_LINE_FULL, sizeof(MSG_I_LINE_FULL)-1, ILINEFULL},
  {MSG_BANNED, sizeof(MSG_BANNED)-1, BANNED},
  {MSG_D_LINED, sizeof(MSG_D_LINED)-1, BANNED},
  {MSG_DRONE_FLOODER, sizeof(MSG_DRONE_FLOODER)-1, DRONE},
  {MSG_X_LINE, sizeof(MSG_X_LINE)-1, XLINEREJ},
  {MSG_INVALID_USERNAME, sizeof(MSG_INVALID_USERNAME)-1, INVALIDUH},
  {MSG_SERVER, sizeof(MSG_SERVER)-1, SERVER},
  {MSG_FAILED_OPER, sizeof(MSG_FAILED_OPER)-1, FAILEDOPER},
  {MSG_INFO_REQUESTED, sizeof(MSG_INFO_REQUESTED)-1, INFOREQUESTED},
  {MSG_NO_ACONF, sizeof(MSG_NO_ACONF)-1, NOACONFFOUND},
  {MSG_QUARANTINED, sizeof(MSG_QUARANTINED)-1, QUARANTINE},
  {NULL, 0, INVALID}
};	

/*
 * on_trace_user()
 * 
 * inputs	- traceline from server
 * output	- NONE
 * side effects	- user is added to hash tables
 * 
 */

void
on_trace_user(int argc, char *argv[])
{
  struct user_entry userinfo;
  char *ip_ptr;
  char *right_bracket_ptr;

  if (tcm_status.doing_trace == NO)
    return;

  /* /trace format the same now everywhere? */
  
  right_bracket_ptr = argv[6]+strlen(argv[6]);

  while(right_bracket_ptr != argv[6])
  {
    if (*right_bracket_ptr == ')')
    {
      *right_bracket_ptr = '\0';
      break;
    }
    right_bracket_ptr--;
  }

  ip_ptr = argv[6]+1;

  while((*ip_ptr != ')') && *ip_ptr)
    ++ip_ptr;

  if (*ip_ptr == ')')
    *ip_ptr = '\0';

  if (!strncmp(argv[5], tcm_status.my_nick, strlen(tcm_status.my_nick)))
  {
    strlcpy(tcm_status.my_class, argv[4], MAX_CLASS);
  }

  chopuh(IS_FROM_TRACE, argv[5], &userinfo);
  strlcpy(userinfo.class, argv[4], MAX_CLASS);
  strlcpy(userinfo.nick, argv[5], MAX_NICK);
  strlcpy(userinfo.ip_host, argv[6]+1, MAX_IP);
  add_user_host(&userinfo, YES);
}

/* 
 * on_stats_i()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- exempt list of tcm is built up from stats I of server
 * 
 */
void
on_stats_i(int argc, char *argv[])
{
  char *user;
  char *host;
  char *p;
  int set_exempt = 0;

  /* N.B. get_user_host modifies argv[6] */
  if (get_user_host(&user, &host, argv[6]) == NULL)
    return;

  /* check for I: exemption flags, and mark exempt in tcm */
  for(p = user; *p != '\0'; p++)
  {
    switch(*p)
    {
      case '^': /* K:/G: Protection (E:) */
      case '>': /* Exempt from user limits (F:) */
      case '_': /* Exempt from G: - XXX should this be here? */
      case '=': /* Spoof...reasoning:  if they're spoofed, they're likely
                 * trustworthy enough to be exempt from tcm's wrath
                 */
	set_exempt = 1;
	break;

      default:
	if(isalnum((int)*p) || *p == '*' || *p == '?' || *p == '~')
	{
          if(set_exempt)
            add_exempt(p, host, 0);

	  return;
	}
        break;
    }
  }
}

/*
 * on_server_notice()
 *
 * inputs	- message from server
 * output	- NONE
 * side effects	-
 */
void
on_server_notice(struct source_client *source_p, int argc, char *argv[])
{
  int i = -1;
  int faction = -1;
  struct user_entry userinfo;
  char *from_server;
  /* XXX - Verify these down below */
  char *nick = NULL;
  char *user = NULL;
  char *host = NULL;
  char *target;
  char *p, *message;
  char *q = NULL;

  if(strcasecmp(source_p->name, tcm_status.my_server) != 0)
    return;

  p = message = argv[argc-1];

  if (strncasecmp(p, "*** Notice -- ", 14) == 0)
    p+=14;

  for (i = 0; msgs_to_mon[i].msg_to_mon; i++)
  {
    if (strncmp(p, msgs_to_mon[i].msg_to_mon, msgs_to_mon[i].len) == 0)
      break;
  }

  if (msgs_to_mon[i].msg_to_mon != NULL)
  {
    q = p + msgs_to_mon[i].len;
    faction = msgs_to_mon[i].action;
  }
  else
    faction = IGNORE;

  if (strstr(p, "I-line mask "))
  {
    if ((q = strrchr(p, '[')) == NULL)
      return;
    if ((p = strrchr(q, ']')) == NULL)
      return;
    ++q;
    *p = '\0';
    /* XXX transition WRONG WRONG WRONG */
    /* who did this, and would you please explain it to me? -bill */
    send_to_connection(config_entries.testline_cnctn,
		    "%s has access to class %s", config_entries.testline_umask, q);
    config_entries.testline_cnctn = NULL;
    memset(&config_entries.testline_umask, 0, sizeof(config_entries.testline_umask));
    return;
  }
  else if (strstr(p, "K-line name "))
  {
    if ((q = strstr(p, "pass [")) == NULL)
      return;
    q+=6;
    if ((p = strchr(q, ']')) == NULL)
      return;
    *p = '\0';
    /* see above */
    send_to_connection(config_entries.testline_cnctn, 
	 "%s has been K-lined: %s", config_entries.testline_umask, q);
    config_entries.testline_cnctn = NULL;
    memset(&config_entries.testline_umask, 0, sizeof(config_entries.testline_umask));
    return;
  }

  if (strstr(p, "is now operator ("))
  {
    if ((q = strchr(p, ' ')) == NULL)
      return;
    if ((p = strchr(q+1, ' ')) == NULL)
      return;
    *p++ = '\0';
    if ((q = strrchr(p, ' ')) == NULL)
      return;
    ++q;
    send_to_all(NULL, FLAGS_WARN, "*** %s has just become an irc operator %s", 
	        message+14, q);
    return;
  }

  /* Kline notice requested by Toast */
  if (strstr(p, "added K-Line for"))
  {
    send_to_all(NULL, FLAGS_VIEW_KLINES, "%s", p);
    tcm_log(L_NORM, "%s", p);
    return;
  }
  else if (strstr(p, "added temporary "))
  {
    send_to_all(NULL, FLAGS_VIEW_KLINES, "%s", p);
    tcm_log(L_NORM, "%s", p);
    return;
  }
  else if (strstr(p, "has removed the "))
  {
    send_to_all(NULL, FLAGS_VIEW_KLINES, "%s", p);
    tcm_log(L_NORM, "%s", p);
    return;
  }

  /* *** Notice -- billy-jon!bill@aloha.from.hilo on irc.intranaut.com is
         requesting gline for [this@is.a.test] [test test2] */
  if (strstr(p, "is requesting gline for "))
  {
    nick = p;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    *q = '\0';

    target = q+4;
    if ((q = strchr(target, ' ')) == NULL)
      return;
    *q = '\0';
    q+=25;
    if ((p = strchr(q, ' ')) == NULL)
      return;
    p+=2;

    if (get_user_host(&user, &host, q) == NULL)
      return;

    if ((q = strchr(p, ']')) == NULL)
      return;
    *q = '\0';
    send_to_all(NULL, FLAGS_VIEW_KLINES,
                "GLINE for %s@%s by %s [%s]: %s", user, host, nick, target, p);
    return;
  }
  /* billy-jon!bill@ummm.E on irc.intranaut.com has triggered gline for [test@this.is.a.test] [test1 test2] */
  else if (strstr(p, "has triggered gline for "))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q++ = '\0';

    p = strstr(q, "has triggered");
    p+=24;

    if ((q = strrchr(p, '[')) == NULL)
      return;
    q++;

    if (get_user_host(&user, &host, p) == NULL)
      return;

    if ((p = strrchr(q, ']')) == NULL)
      return;
    *p = '\0';

    send_to_all(NULL, FLAGS_VIEW_KLINES,
		"GLINE for %s@%s triggered by %s: %s", user, host, nick, q);
    return;
  }

  if (strstr(p, "is rehashing"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q++ = '\0';

    if (strstr(q, " DNS"))
      send_to_all(NULL, FLAGS_SPY, "*** %s is rehashing DNS", nick);
    else
    {
      send_to_all(NULL, FLAGS_SPY, "*** %s is rehashing config file", nick);
      reload_userlist();
    }

    return;
  }
  else if (strstr(p, "clearing temp klines"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(NULL, FLAGS_VIEW_KLINES,
		"*** %s is clearing temp klines", nick);
    return;
  }
  else if (strstr(p, "clearing G-lines"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(NULL, FLAGS_VIEW_KLINES, "*** %s is clearing g-lines", nick);
    return;
  }
  else if (strstr(p, "garbage collecting"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(NULL, FLAGS_SPY, "*** %s is garbage collecting", nick);
    return;
  }
  else if (strstr(p, "forcing re-reading of"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    if ((p = strstr(q, "re-reading of")) == NULL)
      return;
    p+=14;
    send_to_all(NULL, FLAGS_SPY, "*** %is is rehashing %s", nick, p);
    return;
  }

  if (strstr(p, "KILL message for"))
  {
    kill_add_report(p);
    return;
  }

  switch (faction)
  {
  /* Client connecting: bill (bill@ummm.E) [255.255.255.255] {1} */
  /* Client connecting: bill (bill@ummm.E) [255.255.255.255] {opers} [Bill Jonus] */
  case CONNECT:
    p+=19;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    *q++ = '\0';

    strlcpy(userinfo.nick, p, MAX_NICK);

    if ((p = get_user_host(&user, &host, q)) == NULL)
      return;
    strlcpy(userinfo.username, user, MAX_USER);
    strlcpy(userinfo.host, host, MAX_HOST);

    if ((q = strchr(p, '[')) == NULL)
      return;
    q++;
    p = q;

    if ((q = strchr(p, ']')) == NULL)
      return;
    *q++ = '\0';

    strlcpy(userinfo.ip_host, p, MAX_IP);

    if ((p = strchr(q, '{')) == NULL)
      return;
    p++;
    if ((q = strchr(p, '}')) == NULL)
      return;
    *q = '\0';
    strlcpy(userinfo.class, p, MAX_CLASS);

    if (config_entries.hybrid == YES && config_entries.hybrid_version >= 7)
    {
      q += 3;
      if ((p = strrchr(q, ']')) == NULL)
        return;
      *p = '\0';
      strlcpy(userinfo.gecos, q, MAX_GECOS);
    }

    add_user_host(&userinfo, NO);
    break;

  /* Client exiting: bill (bill@ummm.E) [255.255.255.255] */
  /* Client exiting: bill (bill@ummm.E) [Client Quit] [255.255.255.255] */
  case EXITING:
    p+=16;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    *q++ = '\0';

    strlcpy(userinfo.nick, p, MAX_NICK);
    if ((p = get_user_host(&user, &host, q)) == NULL)
      return;
    strlcpy(userinfo.username, user, MAX_USER);
    strlcpy(userinfo.host, host, MAX_HOST);

    if ((q = strrchr(p, '[')) == NULL)
      return;
    q++;

    if ((p = strchr(q, ']')) == NULL)
      return;
    *p = '\0';

    strlcpy(userinfo.ip_host, q, MAX_IP);
#ifdef VIRTUAL
    strlcpy(userinfo.ip_class_c, q, MAX_IP);
#endif
    remove_user_host(&userinfo);
    break;

  /* Unauthorized client connection from bill[bill@localhost] [127.0.0.1]
     on [irc.intranaut.com/6667]. */
  /* Unauthorised client connection from bill[bill@localhost] [127.0.0.1]
     on [irc.intranaut.com/6667]. */
  case UNAUTHORIZED:
    if ((q = strchr(p, '[')) == NULL)
      return;
    for (p=q;*p != ' '; --p);
    ++p;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    *q = '\0';
    chopuh(IS_FROM_TRACE, p, &userinfo);
    log_failure(&userinfo);
    break;

  /* Nick change: From bill to aa [bill@ummm.E] */
  case NICKCHANGE:
    check_nick_flood(q);
    break;

  /* LINKS '' requested by bill (bill@ummm.E) [irc.bill.eagan.mn.us] */
  case LINK_LOOK:
    link_look_notice(q);
    break;

  /* STATS p requested by bill (bill@ummm.E) [irc.bill.eagan.mn.us] */
  case STATS:
    stats_notice(q);
    break;

  case SIGNAL:
    reload_userlist();
    break;

  /* Link with test.server[bill@255.255.255.255] established: (TS) link */ 
  case LINKWITH:
    p+=10
    send_to_all(NULL, FLAGS_SERVERS, "Link with %s", p);
    break;

  /* Received SQUIT test.server from bill[bill@ummm.E] (this is a test) */
  case SQUITOF:
    q=p+15; 
    if ((p = strchr(q, ' ')) == NULL)
      return;
    *p = '\0';
    p+=6;
    send_to_all(NULL, FLAGS_SERVERS, "SQUIT for %s from %s", q, p);
    break;

  /* motd requested by bill (bill@ummm.E) [irc.bill.eagan.mn.us] */
  case MOTDREQ:
    p+=18;
    send_to_all(NULL, FLAGS_SPY, "[MOTD requested by %s]", p);
    break;

  case  IGNORE:
    break;

  /* Flooder bill [bill@ummm.E] on irc.intranaut.com target: #clone */ 
  case FLOODER:
    q=p+8;
    if ((p = strchr(q,' ')) == NULL)
      break;

    *p = '\0';
    p++;
    nick = q;

    if ((q = strchr(p, ' ')) == NULL)
      break;
    from_server = q+4;

    if (get_user_host(&user, &host, p) == NULL)
      break;

    if ((p = strchr(from_server,' ')) == NULL)
      break;
    *p = '\0';
    target = p+9;

    if (strcasecmp(tcm_status.my_server, from_server) == 0)
    {
      send_to_all(NULL, FLAGS_WARN,
		  "*** Flooder %s (%s@%s) target: %s",
		  nick, user, host, target);
      handle_action(act_flood, nick, user, host, 0, 0);
    }

    break;

  /* User bill (bill@ummm.E) is a possible spambot */
  /* User bill (bill@ummm.E) trying to join #tcm is a possible spambot */
  case SPAMBOT:
    q=p+5;
    if ((p = strchr(q,' ')) == NULL)
      return;
    *p++ = '\0';

    nick = q;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    q++;

    if (get_user_host(&user, &host, p) == NULL)
      return;

    if (strstr(q, "possible spambot") == NULL)
      return;

    send_to_all(NULL, FLAGS_ALL, "Spambot: %s (%s@%s)", nick, user, host);

    handle_action(act_spambot, nick, user, host, 0, 0);
    break;

  /* I-line is full for bill[bill@ummm.E] (127.0.0.1). */
  case ILINEFULL:
    nick = p+19;
    connect_flood_notice(nick, "I line full");
    break;

  /* *** You have been D-lined */
  /* *** Banned: this is a test (2002/04/11 15.10) */
  case BANNED:
    send_to_all(NULL, FLAGS_ALL, "I am banned from %s.  Exiting..", 
		tcm_status.my_server ?
		tcm_status.my_server : config_entries.server_name);
    tcm_log(L_ERR, "%s", "onservnotice Banned from server.  Exiting.");
    exit(-1);
    /* NOT REACHED */
    break;

  /* Possible Drone Flooder bill [bill@ummm.E] on irc.intranaut.com target:
     #clone */
  case DRONE:
    nick = p + 23;

    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q++ = '\0';

    if ((p = strchr(q, ']')) == NULL)
      return;
    p+=5;

    if (get_user_host(&user, &host, q) == NULL)
      return;

    from_server = p;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    *q = '\0';
    q+=9;

    if (strcasecmp(from_server, tcm_status.my_server))
      return;

    send_to_all(NULL, FLAGS_WARN,
		"Possible drone flooder: %s!%s@%s target: %s",
		nick, user, host, q);
    break;

  /* X-line Rejecting [Bill Jonus] [just because] user bill[bill@ummm.E] */
  case XLINEREJ:
    q=p+18;
    if ((nick = strrchr(q, ' ')) == NULL)
      return;
    ++nick;
    connect_flood_notice(nick, "X-Line rejections");
    break;

  /* Quarantined nick [bill] from user aa[bill@ummm.E] */
  case QUARANTINE:
    nick = p+18; 
    connect_flood_notice(nick, "Quarantined nick");
    break;

  /* Invalid username: bill (!@$@&&&.com) */
  case INVALIDUH:
    nick = p+18;
    connect_flood_notice(nick, "Invalid user@host");
    break;

  /* Server ircd.flamed.net split from ircd.secsup.org */
  /* Server irc.intranaut.com being introduced by ircd.secsup.org */
  case SERVER:
    q=p+7;
    if (strstr(q, "split"))
    {
      nick = q;
      if ((q = strchr(nick, ' ')) == NULL)
        return;
      *q = '\0';
      user = q+12;
      send_to_all(NULL, FLAGS_SERVERS, "Server %s split from %s", nick, user);
    }
    else if (strstr(q, "being introduced"))
    {
      nick = q;
      if ((q = strchr(nick, ' ')) == NULL)
        return;
      *q = '\0';
      user = q+21;
      send_to_all(NULL, FLAGS_SERVERS,
		  "Server %s being introduced by %s", nick, user);
    }
    break;

  /* Failed OPER attempt by bill (bill@holier.than.thou) */
  case FAILEDOPER:
    nick = p+23;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    user = q+1;
    send_to_all(NULL, FLAGS_WARN,
		"*** Failed oper attempt by %s %s", nick, user);
    break;

  /* info requested by bill (bill@ummm.e) [irc.bill.eagan.mn.us] */
  case INFOREQUESTED:
    nick = p+18;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    user = q+2;
    if ((q = strchr(user, ')')) == NULL)
      return;
    *q = '\0';
    send_to_all(NULL, FLAGS_SPY, "[INFO requested by %s (%s)]", nick, user);
    break;

  /* No aconf found */
  case NOACONFFOUND:
    send_to_connection(config_entries.testline_cnctn,
		    "%s does not have access", config_entries.testline_umask);
    config_entries.testline_cnctn = NULL;
    memset(&config_entries.testline_umask, 0, sizeof(config_entries.testline_umask));
    break;

  default:
    if ((p = strstr(message, "*** Notice -- ")))
      p += 14;
    else
      p = message;
    send_to_all(NULL, FLAGS_NOTICE, "Notice: %s", p);
    break;
  }
}


/*
 * connect_flood_notice
 *
 * input	- pointer to notice
 *		- pointer to reason to hand to actions
 * output	- none
 * side effects	-
 */
static void
connect_flood_notice(char *snotice, char *reason)
{
  char *nick_reported;
  char *user_host;
  char *user;
  char *host;
  char *p;

  int first_empty_entry = -1;
  int found_entry = NO;
  int i;

  p= nick_reported= snotice;
  while (*p != ' ' && *p != '[')
    ++p;
  user_host=p+1;

  if (get_user_host(&user, &host, user_host) == NULL)
    return;

  for(i=0; i<MAX_CONNECT_FAILS; ++i)
    {
      if (connect_flood[i].user[0] != '\0')
	{
	  if ((strcasecmp(connect_flood[i].user, user) == 0) &&
	      (strcasecmp(connect_flood[i].host, host) == 0))
	    {
	      found_entry = YES;

	      if ((connect_flood[i].last_connect + MAX_CONNECT_TIME)
		  < current_time)
		{
		  connect_flood[i].connect_count = 0;
		}

	      connect_flood[i].connect_count++;
	      if (connect_flood[i].connect_count >= MAX_CONNECT_FAILS)
		handle_action(act_cflood, nick_reported, user, host, 0, reason);
	    }
	  else if ((connect_flood[i].last_connect + MAX_CONNECT_TIME)
		   < current_time)
	    {
	      connect_flood[i].user[0] = '\0';
	      connect_flood[i].host[0] = '\0';
	    }
	}
      else if (first_empty_entry < 0)
	{
	  first_empty_entry = i;
	}
    }

  if (!found_entry)
    {
      if (first_empty_entry >= 0)
	{
	  strlcpy(connect_flood[first_empty_entry].user, user, MAX_USER);
	  strlcpy(connect_flood[first_empty_entry].host, host, MAX_HOST);
	  connect_flood[first_empty_entry].last_connect = current_time;
	  connect_flood[first_empty_entry].connect_count = 0;
	}
    }
}

/*
 * link_look_notice
 *
 * inputs	- rest of notice from server
 * output	- NONE
 * side effects
 *
 *  What happens here: There is a fixed sized table of MAX_LINK_LOOKS
 * each with a struct link_look_entry. Both the expiry of old old link
 * entries is made, plus the search for an empty slot to stick a possible
 * new entry into. If the user@host entry is NOT found in the table
 * then an entry is made for this user@host, and is time stamped.
 *
 */
static void
link_look_notice(char *snotice)
{
  char *nick_reported;
  char *user;
  char *host;
  char *seen_user_host;
  int first_empty_entry = -1;
  int found_entry = NO;
  int i;

  if ((nick_reported = strstr(snotice,"requested by")) == NULL)
    return;

  nick_reported += 13;

  if ((seen_user_host = strchr(nick_reported,' ')) == NULL)
    return;
  *seen_user_host++ = '\0';

  if (get_user_host(&user, &host, seen_user_host) == NULL)
    return;

  send_to_all(NULL, FLAGS_SPY, "[LINKS by %s (%s@%s)]",
	      nick_reported, user, host ); /* - zaph */

  for(i = 0; i < MAX_LINK_LOOKS; i++ )
    {
      if (link_look[i].user[0] != '\0')
	{
	  if ((strcasecmp(link_look[i].user,user) != 0) &&
	      (strcasecmp(link_look[i].host,host) != 0))
	    {
	      found_entry = YES;

	      if ((link_look[i].last_link_look + MAX_LINK_TIME) < current_time)
		{
		  link_look[i].link_look_count = 0;
		}

	      link_look[i].link_look_count++;
	      
	      if (link_look[i].link_look_count >= MAX_LINK_LOOKS)
		{
		  handle_action(act_link,
				nick_reported, user, host, 0, 0);
		  /* the client is dead now */
		  link_look[i].user[0] = '\0';
		  link_look[i].host[0] = '\0';
		}
	      else
		{
		  link_look[i].last_link_look = current_time;
		}
	    }
	  else
	    {
	      if ((link_look[i].last_link_look + MAX_LINK_TIME) < current_time)
		{
		  link_look[i].user[0] = '\0';
		  link_look[i].host[0] = '\0';
		}
	    }
	}
      else
	{
	  if (first_empty_entry < 0)
	    first_empty_entry = i;
	}
    }

/*
 *  If this is a new entry, then found_entry will still be NO
 */

  if (!found_entry)
    {
      if (first_empty_entry >= 0)
	{
	  /* XXX */
	  strlcpy(link_look[first_empty_entry].user,user,MAX_USER);
	  strlcpy(link_look[first_empty_entry].user,host,MAX_USER);
	  link_look[first_empty_entry].last_link_look = current_time;
          link_look[first_empty_entry].link_look_count = 1;
	}
    }
}

/*
 * cs_clones
 *
 * inputs	- notice
 * output	- none
 * side effects
 * connected opers are dcc'ed a suggested kline
 *
 */
static void
cs_clones(char *snotice)
{
  char *nick_reported;
  char *user_host;
  char *user;
  char *host;

  if ((nick_reported = strchr(snotice,' ')) == NULL)
    return;
  nick_reported++;

  if ((user_host = strchr(nick_reported,' ')) == NULL)
    return;

  if (get_user_host(&user, &host, user_host) == NULL)
    return;

  send_to_all(NULL, FLAGS_WARN, "CS clones user_host = [%s]", user_host);
  tcm_log(L_NORM, "CS clones = [%s]", user_host);

  handle_action(act_clone, "", user, host, 0, 0);
}

/*
 * check_nick_flood()
 *
 * inputs	- rest of notice from server
 * output	- NONE
 * side effects
 *
 * Audited for H6, H7, cs.
 * Nick change: From bill to aa [bill@ummm.E] */
 */

static void
check_nick_flood(char *snotice)
{
  char *p;
  char *nick1;
  char *nick2;
  char *user_host;
  char *user;
  char *host;

  nick1 = snotice+18;
  if ((p = strchr(nick1, ' ')) == NULL)
    return;

  *p = '\0';
  nick2 = p+4;

  if ((p = strchr(nick2, ' ')) == NULL)
    return;

  *p = '\0';
  user_host = p+2;

  if ((p = strrchr(user_host, ']')) == NULL)
    return;

  *p = '\0';

  if (get_user_host(&user, &host, user_host) == NULL)
    return;

  add_to_nick_change_table(user, host, nick2);
  update_nick(user, host, nick1, nick2);
}

/*
 * init_link_look_table()
 *
 * inputs - NONE
 * output - NONE
 * side effects - clears out the link looker change table
 *
 */
void
init_link_look_table()
{
  int i;

  for(i = 0; i < LINK_LOOK_TABLE_SIZE; i++)
    link_look[i].host[0] = link_look[i].user[0] = '\0';
}

/*
 * add_to_nick_change_table()
 *
 * inputs       - user_host i.e. user@host
 * 	        - last_nick last nick change
 * output	- NONE
 * side effects - add to list of current nick changers
 * 
 *   What happens here is that a new nick is introduced for
 * an already existing user, or a possible nick flooder entry is made.
 * When a new possible nick flooder entry is made, the entry
 * is time stamped with its creation. Already present entries
 * get updated with the current time "last_nick_change"
 *
 *   Expires of already existing nick entries was combined in this
 * loop and in the loop in report_nick_flooders() (i.e. no more
 * expire nick_table.. as in previous versions)
 * at the suggestion of Shadowfax, (mpearce@varner.com)
 * 
 *  What happens is that add_to_nick_change_table() is called
 * at the whim of nick change notices, i.e. not from a timer.
 * (similar applies to report_nick_flooders(), when expires are done)
 *
 * Every NICK_CHANGE_T1_TIME, (defaulted to 10 seconds in config.h)
 * one nick change count is decremented from the nick change count
 * for each user in list. Since this function is called asynchronously,
 * I have to calculate how many "time_ticks" i.e. how many 10
 * second intervals have passed by since the entry was last examined.
 * 
 *  If an entry is really stale, i.e. nothing has changed in it in
 * NICK_CHANGE_T2_TIME it is just completely thrown out.
 * This code is possibly, uneeded. I am paranoid. The idea here
 * is that if someone racks up a lot of nick changes in a brief
 * amount of time, but stop (i.e. get killed, flooded off, klined :-) )
 * Their entry doesn't persist longer than five minutes.
 *
 */

static void
add_to_nick_change_table(char *user, char *host,char *last_nick)
{
  int i;
  int found_empty_entry=-1;

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
  {
    if (nick_changes[i].user[0] != '\0')
    {
      time_t time_difference;
      int time_ticks;

      time_difference = current_time - nick_changes[i].last_nick_change;

      /* is it stale ? */
      if (time_difference >= NICK_CHANGE_T2_TIME)
      {
	nick_changes[i].user[0] = '\0';
	nick_changes[i].host[0] = '\0';
	nick_changes[i].noticed = NO;
      }
      else
      {
	/* how many 10 second intervals do I have? */
	time_ticks = time_difference / NICK_CHANGE_T1_TIME;

	/* is it stale? */
	if (time_ticks >= nick_changes[i].nick_change_count)
	{
	  nick_changes[i].user[0] = '\0';
	  nick_changes[i].host[0] = '\0';
	  nick_changes[i].noticed = NO;
	}
	else
	{
	  /* just decrement 10 second units of nick changes */
	  nick_changes[i].nick_change_count -= time_ticks;

	  if ((strcasecmp(nick_changes[i].user, user) == 0) &&
	      (strcasecmp(nick_changes[i].host, host) == 0))
	  {
	    nick_changes[i].last_nick_change = current_time;
	    (void)strlcpy(nick_changes[i].last_nick, last_nick, MAX_NICK);
	    nick_changes[i].nick_change_count++;
	  }

	  /* now, check for a nick flooder */
	  
	  if ((nick_changes[i].nick_change_count >=
	       NICK_CHANGE_MAX_COUNT)
	      && !nick_changes[i].noticed)
	  {
	    send_to_all(NULL, FLAGS_WARN,
			"nick flood %s@%s (%s) %d in %d seconds (%s)",
			nick_changes[i].user,
			nick_changes[i].host,
			nick_changes[i].last_nick,
			nick_changes[i].nick_change_count,
			nick_changes[i].last_nick_change -
			nick_changes[i].first_nick_change,
			hour_minute_second(nick_changes[i].last_nick_change));

	    handle_action(act_flood, last_nick, user, host, 0, 0);
	    tcm_log(L_NORM,
		    "nick flood %s@%s (%s) %d in %d seconds (%s)",
		    nick_changes[i].user,
		    nick_changes[i].host,
		    nick_changes[i].last_nick,
		    nick_changes[i].nick_change_count,
		    nick_changes[i].last_nick_change -
		    nick_changes[i].first_nick_change,
		    date_stamp());
	    nick_changes[i].noticed = YES;
	  }
	}
      }
    }
    else
    {
      if (found_empty_entry < 0)
	found_empty_entry = i;
    }
  }

/* If the table is full, don't worry about this nick change for now
 * if this nick change is part of a flood, it will show up
 * soon enough anyway... -db
 */

  if (found_empty_entry > 0)
  {
    nick_changes[found_empty_entry].first_nick_change = current_time;
    nick_changes[found_empty_entry].last_nick_change = current_time;
    nick_changes[found_empty_entry].nick_change_count = 1;
    nick_changes[found_empty_entry].noticed = NO;
  }
}

/*
 * stats_notice
 * 
 * inputs		- notice
 * output		- none
 * side effects 	-
 */

static void
stats_notice(char *snotice)
{
  char *nick;
  char *fulluh;
  char *p;
  int stat;

#ifdef DEBUGMODE
  printf("stats_notice(\"%s\")\n", snotice);
#endif

  stat = *(snotice + 6);

  if ((nick = strstr(snotice,"by")) == NULL)
    return;

  nick += 3;

  if ((p = strchr(nick, ' ')) != NULL)
    *p = '\0';
  p++;

  fulluh = p;
  if (*fulluh == '(')
    fulluh++;

  if ((p = strchr(fulluh,')')) != NULL)
    *p = '\0';

#ifdef STATS_P
  if (stat == 'p')
    show_stats_p((const char *)nick);
#endif
  send_to_all(NULL, FLAGS_SPY, "[STATS %c requested by %s (%s)]",
	      stat, nick, fulluh);
}

void
init_bothunt(void)
{
  memset(&nick_changes,0,sizeof(nick_changes));
  memset(&reconnect_clone,0, sizeof(reconnect_clone));
  init_link_look_table();
  init_actions();
  add_serv_notice_handler(&servnotice_msgtab);
}

/*
 * clear_bothunt
 *
 * inputs       - NONE
 * output       - NONE
 * side effects - nick change table is cleared out
 */

void
clear_bothunt(void)
{
  int i;

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
    {
      nick_changes[i].user[0] = '\0';
      nick_changes[i].host[0] = '\0';
      nick_changes[i].noticed = NO;
    }
}

/*
 * report_nick_flooders
 *
 * inputs       - socket to use
 * output       - NONE
 * side effects - list of current nick flooders is reported
 *
 *  Read the comment in add_to_nick_change_table as well.
 */

void 
report_nick_flooders(struct connection *connection_p)
{
  int i;
  int reported_nick_flooder= NO;
  time_t time_difference;
  int time_ticks;

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
    {
      if (nick_changes[i].user[0] != '\0')
        {
          time_difference = current_time - nick_changes[i].last_nick_change;

          /* is it stale ? */
          if(time_difference >= NICK_CHANGE_T2_TIME)
            {
              nick_changes[i].user[0] = nick_changes[i].host[0] = '\0';
            }
          else
            {
              /* how many 10 second intervals do we have? */
              time_ticks = time_difference / NICK_CHANGE_T1_TIME;

              /* is it stale? */
              if(time_ticks >= nick_changes[i].nick_change_count)
                {
		  nick_changes[i].user[0] = nick_changes[i].host[0] = '\0';
                }
              else
                {
                  /* just decrement 10 second units of nick changes */
                  nick_changes[i].nick_change_count -= time_ticks;
                  if( nick_changes[i].nick_change_count > 1 )
                    {
                      send_to_connection(connection_p,
					 "user: %s@%s (%s) %d in %d",
					 nick_changes[i].user,
					 nick_changes[i].host,
					 nick_changes[i].last_nick,
					 nick_changes[i].nick_change_count,
					 nick_changes[i].last_nick_change  -
					 nick_changes[i].first_nick_change);
                      reported_nick_flooder = YES;
                    }
                }
            }
        }
    }

  if(!reported_nick_flooder)
    {
      send_to_connection(connection_p, "No nick flooders found" );
    }
}


/*
 * get_user_host
 *
 * inputs	- user_host pointer to string of form
 *		  (user@host) or
 *		  [user@host] or even plain old
 *		  user@host
 * outputs	- pointer to end char +1
 *		- pointer to user
 *		- pointer to host
 * side effects	- input user_host is modified in place
 */

char *
get_user_host(char **user_p, char **host_p, char *user_host)
{
  char *user = user_host;
  char *end_p = NULL;
  char *p;

  /* either: [user@host] (user@host) or just user@host */
  if (*user == '[')
    {
      user++;
      if ((p = strchr(user, ']')) == NULL)
	return(NULL);
      *p++ = '\0';
      end_p = p;
    }
  else if (*user == '(')
    {
      user++;
      if ((p = strchr(user, ')')) == NULL)
	return(NULL);
      *p++ = '\0';
      end_p = p;
    }

  *user_p = user;

  if ((p = strchr(user, '@')) == NULL)
    return(NULL);

  *p++ = '\0';
  *host_p = p; 
  return (end_p);
}

/*
 *   Chop a string of form "nick [user@host]" or "nick[user@host]" into
 *   nick and userhost parts.  Return pointer to userhost part.  Nick
 *   is still pointed to by the original param.  Note that since [ is a
 *   valid char for both nicks and usernames, this is non-trivial.
 */

static void 
chopuh(int is_trace,char *nickuserhost,struct user_entry *userinfo)
{
  char *uh;
  char *p;
  char skip = NO;
  char *right_brace_pointer;
  char *right_square_bracket_pointer;
  char *user;
  char *host;
/* I try to pick up an [IP] from a connect or disconnect message
 * since this routine is also used on trace, some heuristics are
 * used to determine whether the [IP] is present or not.
 * *sigh* I suppose the traceflag could be used to not even go
 * through these tests
 * bah. I added a flag -Dianora
 */

  userinfo->username[0] = '\0';
  userinfo->host[0] = '\0';
  userinfo->ip_host[0] = '\0';

  /* ok, if its a hybrid server or modified server,
   * I go from right to left picking up extra bits
   * [ip] {class}, then go and pick up the nick!user@host bit
   */

  if(!is_trace)  /* trace output is not the same as +c output */
    {
      /* a strcpy is acceptable IFF you know the sizes will always fit ! */
      strcpy(userinfo->class, "unknown");

      p = nickuserhost;
      while(*p)
        p++;

      right_square_bracket_pointer = NULL;
      right_brace_pointer = NULL;

      while(p != nickuserhost)
        {
          if(right_square_bracket_pointer == NULL)
            if(*p == ']')       /* found possible [] IP field */
              right_square_bracket_pointer = p;

          if(*p == '}') /* found possible {} class field */
            right_brace_pointer = p;

          if(*p == ')') /* end of scan for {} class field and [] IP field */
            break;
          p--;
        }

      if(right_brace_pointer)
        {
          p = right_brace_pointer;
          *p = '\0';
          p--;
          while(p != nickuserhost)
            {
              if(*p == '{')
                {
                  p++;
                  if (*p == ' ') p++;
                  snprintf(userinfo->class, sizeof(userinfo->class) - 1,
                           "%s", p);
                  break;
                }
              p--;
            }
        }

      if(right_square_bracket_pointer && config_entries.hybrid)
        {
          p = right_square_bracket_pointer;
          *p = '\0';
          p--;
          while(p != nickuserhost)
            {
              if(*p == '[')
                {
                  *p = '\0';
                  p++;
                  break;
                }
              else if(*p == '@') /* nope. this isn't a +c line */
                {
                  p = NULL;
                  break;
                }
              else
                p--;
          }
        if (p)
          snprintf(userinfo->ip_host, sizeof(userinfo->ip_host), "%s", p);
      }
    }

  /* If it's the first format, we have no problems */
  if((uh = strchr(nickuserhost,' ')) == NULL)
    {
      if((uh = strchr(nickuserhost,'[')) == NULL)
        {
          /* no [, no (, god knows what the separator is */
          if((uh = strchr(nickuserhost,'(')) == NULL)
            {

              /* XXX - stderr?  shouldnt this be a logfile? --fl_ */
#if 0
              (void)fprintf(stderr,
                            "You have VERY badly screwed up +c output!\n");
              (void)fprintf(stderr,
                            "1st case nickuserhost = [%s]\n", nickuserhost);
#endif
              return;           /*screwy...prolly core in the caller*/
            }

	  /* there was a (, uh points to it.  shift uh up one */
	  *uh++ = '\0';

	  /* search for the ) to match and replace with \0 */
          if((p = strrchr(uh,')')) != NULL)
            {
              *p = '\0';
            }
          else
            {
	      /* XXX - stderr? logfile? */
#if 0
              (void)fprintf(stderr,
                            "You have VERY badly screwed up +c output!\n");
              (void)fprintf(stderr,
                            "No ending ')' nickuserhost = [%s]\n",
                            nickuserhost);
#endif
              /* No ending ')' found, but lets try it anyway */
            }

          if (get_user_host(&user, &host, uh) == 0)
	    return;
	  strlcpy(userinfo->username, user, MAX_USER);
	  strlcpy(userinfo->host, host, MAX_HOST);
          return;
        }

      /* there *was* a [ as the separator, uh points to it */

      /* theres another one.  ugh. */
      if (strchr(uh+1,'[') != NULL)
        {
          /*moron has a [ in the nickname or username.  Let's do some AI crap*/
          if ((uh = strchr(uh, '~')) == NULL)
            {
              /* no tilde to guess from:
	       *
	       * the chances of the [ being in their nick is higher than it
	       * being in their ident, so presume it marks the end.
	       *
	       * if we're wrong?  no big deal. --fl_
	       */
              uh = strrchr(nickuserhost, '[');
#if 0
                while (--uh != nickuserhost)
                  if (*uh == '[' && uh - nickuserhost < 10)
                    break;
#endif
            }
	  /* uh points to the leading ~ */
          else
            {
              /* We have a ~ which is illegal in a nick, but also valid
               * in a faked username.  Assume it is the marker for the start
               * of a non-ident username, which means a [ should precede it.
               */
              if (*(uh-1) == '[')
                {
                  --uh;
                }
              else
                /* Idiot put a ~ in his username AND faked identd.  Take the
                 * first [ that precedes this, unless it creates an
                 *  illegal length username or nickname
                 */
                while (--uh != nickuserhost)
                  if (*uh == '[' && uh - nickuserhost < 10)
                    break;
            }
        }
    }
  else
    skip = YES;

  *(uh++) = '\0';
  if (skip)
    ++uh;                 /* Skip [ */
  if (strchr(uh,' '))
    *(strchr(uh,' ')) = '\0';
  if (uh[strlen(uh)-1] == '.')
    uh[strlen(uh)-2] = '\0';   /* Chop ] */
  else
    uh[strlen(uh)-1] = '\0';   /* Chop ] */

  if (get_user_host(&user, &host, uh) == 0)
    return;
  strlcpy(userinfo->username, user, MAX_USER);
  strlcpy(userinfo->host, host, MAX_HOST);
}
