/* bothunt.c
 *
 * $Id: bothunt.c,v 1.169 2002/06/21 14:07:37 leeh Exp $
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
static void cs_nick_flood(char *snotice);
static void cs_clones(char *snotice);
static void link_look_notice(char *snotice);
static void connect_flood_notice(char *snotice, char *reason);
static void add_to_nick_change_table(char *user_host, char *last_nick);
static void stats_notice(char *snotice);
static void chopuh(int istrace,char *nickuserhost,struct user_entry *userinfo);
#define IS_FROM_TRACE		YES
#define IS_NOT_FROM_TRACE	NO

struct serv_command servnotice_msgtab = {
  "NOTICE", NULL, on_server_notice
};

struct s_testline testlines;

struct nick_change_entry
{
  char user_host[MAX_USERHOST];
  char last_nick[MAX_NICK];
  int  nick_change_count;
  time_t first_nick_change;
  time_t last_nick_change;
  int noticed;
};


static struct nick_change_entry nick_changes[NICK_CHANGE_TABLE_SIZE];


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
  {MSG_NICK_FLOODING, sizeof(MSG_NICK_FLOODING)-1, CS_NICKFLOODING},
  {MSG_REJECTING, sizeof(MSG_REJECTING)-1, CS_CLONES},
  {MSG_CLONEBOT_KILLED, sizeof(MSG_CLONEBOT_KILLED)-1, CS_CLONEBOT_KILLED},
  {MSG_IDLE_TIME, sizeof(MSG_IDLE_TIME)-1, IGNORE},
  {MSG_LINKS, sizeof(MSG_LINKS)-1, LINK_LOOK},
  {MSG_KLINE, sizeof(MSG_KLINE)-1, IGNORE},  
  {MSG_STATS, sizeof(MSG_STATS)-1, STATS},
  {MSG_GOT_SIGNAL, sizeof(MSG_GOT_SIGNAL)-1, SIGNAL},
  {MSG_NICK_COLLISION, sizeof(MSG_NICK_COLLISION)-1, IGNORE},
  {MSG_SEND_MESSAGE, sizeof(MSG_SEND_MESSAGE)-1, IGNORE},
  {MSG_GHOSTED, sizeof(MSG_GHOSTED)-1, IGNORE},
  {MSG_CONNECT_FAILURE, sizeof(MSG_CONNECT_FAILURE)-1, IGNORE},
  {MSG_INVISIBLE_CLIENT, sizeof(MSG_INVISIBLE_CLIENT)-1, IGNORE},
  {MSG_OPER_COUNT_OFF, sizeof(MSG_OPER_COUNT_OFF)-1, IGNORE},
  {MSG_USER_COUNT_OFF, sizeof(MSG_USER_COUNT_OFF)-1, IGNORE},
  {MSG_LINK_WITH, sizeof(MSG_LINK_WITH)-1, LINKWITH},
  {MSG_SQUIT, sizeof(MSG_SQUIT)-1, SQUITOF},
  {MSG_MOTD, sizeof(MSG_MOTD)-1, MOTDREQ},
  {MSG_FLOODER, sizeof(MSG_FLOODER)-1, FLOODER},
  {MSG_USER, sizeof(MSG_USER)-1, SPAMBOT},
  {MSG_I_LINE_MASK, sizeof(MSG_I_LINE_MASK)-1, IGNORE},
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

struct connect_flood_entry connect_flood[CONNECT_FLOOD_TABLE_SIZE];

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
  int  is_oper;
  char *ip_ptr;
  char *right_bracket_ptr;

  if (tcm_status.doing_trace == NO)
    return;

  if (argv[3][0] == 'O')
    is_oper = YES;
  else
    is_oper = NO;

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
  add_user_host(&userinfo, YES, is_oper);
}

/* 
 * on_stats_e()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- exception list of tcm is built up from stats E of server
 * 
 */
void
on_stats_e(int argc, char *argv[])
{
  char *user;
  char *host;
  char body[MAX_BUFF];

  expand_args(body, MAX_BUFF, argc, argv);

/* No point if I am maxed out going any further */
  if (host_list_index >= (MAXHOSTS - 1))
    return;

  if ((strtok(body," ") == NULL) )		/* discard this field */
    return;

  /* should be 'E' */
    
  if ((host = strtok(NULL," ")) == NULL)
    return;

  if ((strtok(NULL," ") == NULL))
    return;

  if ((user = strtok(NULL," ")) == NULL)	/* NOW user */
    return;

  strlcpy(hostlist[host_list_index].user, user,
	  sizeof(hostlist[host_list_index].user));

  strlcpy(hostlist[host_list_index].host, host,
	  sizeof(hostlist[host_list_index].host));

  host_list_index++;
}

/* 
 * on_stats_i()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- exception list of tcm is built up from stats I of server
 * 
 */
void
on_stats_i(int argc, char *argv[])
{
  char *user;
  char *host;

  /* No point if I am maxed out going any further */
  if (host_list_index >= (MAXHOSTS - 1))
    return;

  /* N.B. get_user_host modifies argv[6] */
  if (get_user_host(&user, &host, argv[6]) == 0)
    return;

  /* if client is exempt, mark it as such in the exemption list */

  if(isalnum((int)(*user)))
    return;

  strlcpy(hostlist[host_list_index].user, user, MAX_NICK);
  strlcpy(hostlist[host_list_index].host, host, MAX_HOST);
  hostlist[host_list_index].type = (unsigned int) ~0;

  host_list_index++;
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
    print_to_socket(connections[testlines.index].socket,
		    "%s has access to class %s", testlines.umask, q);
    testlines.index = -1;
    memset(&testlines.umask, 0, sizeof(testlines.umask));
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
    print_to_socket(connections[testlines.index].socket, 
	 "%s has been K-lined: %s", testlines.umask, q);
    testlines.index = -1;
    memset(&testlines.umask, 0, sizeof(testlines.umask));
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
    send_to_all(FLAGS_WARN, "*** %s has just become an irc operator %s", 
	        message+14, q);
    return;
  }

  /* Kline notice requested by Toast */
  if (strstr(p, "added K-Line for"))
  {
    tcm_log(L_NORM, "%s", p);
    return;
  }
  else if (strstr(p, "added temporary "))
  {
    tcm_log(L_NORM, "%s", p);
    return;
  }
  else if (strstr(p, "has removed the "))
  {
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

    if (get_user_host(&user, &host, q) != 1)
      return;

    if ((q = strchr(p, ']')) == NULL)
      return;
    *q = '\0';
    send_to_all(FLAGS_VIEW_KLINES,
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

    if (get_user_host(&user, &host, p) != 1)
      return;

    if ((p = strrchr(q, ']')) == NULL)
      return;
    *p = '\0';

    send_to_all(FLAGS_VIEW_KLINES,
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
      send_to_all(FLAGS_SPY, "*** %s is rehashing DNS", nick);
    else
    {
      send_to_all(FLAGS_SPY, "*** %s is rehashing config file", nick);
      print_to_server("STATS Y");
    }
    return;
  }
  else if (strstr(p, "clearing temp klines"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(FLAGS_VIEW_KLINES, "*** %s is clearing temp klines", nick);
    return;
  }
  else if (strstr(p, "clearing G-lines"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(FLAGS_VIEW_KLINES, "*** %s is clearing g-lines", nick);
    return;
  }
  else if (strstr(p, "garbage collecting"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(FLAGS_SPY, "*** %s is garbage collecting", nick);
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
    send_to_all(FLAGS_SPY, "*** %is is rehashing %s", nick, p);
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
  case CONNECT:
    if ((q = strchr(p, '(')) == NULL)
      return;
    *(q-1) = '\0';
    strlcpy(userinfo.nick, p+19, MAX_NICK);;
    if ((p = strchr(q, '[')) == NULL)
      return;
    ++p;

    if (get_user_host(&user, &host, q) != 1)
      return;

    strlcpy(userinfo.user, user, MAX_USER);
    strlcpy(userinfo.host, host, MAX_HOST);

    if ((q = strchr(p, ']')) == NULL)
      return;
    *q++ = '\0';

    strcpy((char *)&userinfo.ip_host, p);

    if ((p = strchr(q, '{')) == NULL)
      return;
    p++;
    if ((q = strchr(p, '}')) == NULL)
      return;
    *q = '\0';

    strcpy((char *)&userinfo.class, p);

    add_user_host(&userinfo, NO, NO);
    break;

  /* Client exiting: bill (bill@ummm.E) [e?] [255.255.255.255]*/
  case EXITING:
    chopuh(IS_NOT_FROM_TRACE, q, &userinfo);
    remove_user_host(q,&userinfo);
    break;

  /* Unauthorized client connection from bill[bill@localhost] [127.0.0.1]
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

/* CS style of reporting nick flooding */
  case CS_NICKFLOODING:
    cs_nick_flood(q);
    break;

  case CS_CLONES:
  case CS_CLONEBOT_KILLED:
    cs_clones(q);
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
    print_to_server("STATS Y");
    break;

  /* Link with test.server[bill@255.255.255.255] established: (TS) link */ 
  case LINKWITH:
    ++q;
    send_to_all(FLAGS_SERVERS, "Link with %s", q);
    break;

  /* Received SQUIT test.server from bill[bill@ummm.E] (this is a test) */
  case SQUITOF:
    ++q;
    if ((p = strchr(q, ' ')) == NULL)
      return;
    *p = '\0';
    p+=6;
    send_to_all(FLAGS_SERVERS, "SQUIT for %s from %s", q, p);
    break;

  /* motd requested by bill (bill@ummm.E) [irc.bill.eagan.mn.us] */
  case MOTDREQ:
    ++q;
    send_to_all(FLAGS_SPY, "[MOTD requested by %s]", q);
    break;

  case  IGNORE:
    break;

  /* Flooder bill [bill@ummm.E] on irc.intranaut.com target: #clone */ 
  case FLOODER:
    ++q;
    if ((p = strchr(q,' ')) == NULL)
      break;

    *p = '\0';
    p++;
    nick = q;

    if ((q = strchr(p, ' ')) == NULL)
      break;
    from_server = q+4;

    if (get_user_host(&user, &host, p) != 1)
      break;

    if ((p = strchr(from_server,' ')) == NULL)
      break;
    *p = '\0';
    target = p+9;

    if (strcasecmp(tcm_status.my_server, from_server) == 0)
    {
      send_to_all(FLAGS_WARN,
		   "*** Flooder %s (%s@%s) target: %s",
		   nick, user, host, target);
      handle_action(act_flood, nick, user, host, 0, 0);
    }

    break;

  /* User bill (bill@ummm.E) is a possible spambot */
  /* User bill (bill@ummm.E) trying to join #tcm is a possible spambot */
  case SPAMBOT:
    ++q;
    if ((p = strchr(q,' ')) == NULL)
      return;
    *p++ = '\0';

    nick = q;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    q++;

    if (get_user_host(&user, &host, p) != 1)
      return;

    if (strstr(q, "possible spambot") == NULL)
      return;

    send_to_all(FLAGS_ALL, "Spambot: %s (%s@%s)", nick, user, host);

    handle_action(act_spambot, nick, user, host, 0, 0);
    break;

  /* I-line is full for bill[bill@ummm.E] (127.0.0.1). */
  case ILINEFULL:
    /* XXX */
    nick = q+1; /* XXX confirm */
    connect_flood_notice(nick, "I line full");
    break;

  /* *** You have been D-lined */
  /* *** Banned: this is a test (2002/04/11 15.10) */
  case BANNED:
    send_to_all(FLAGS_ALL, "I am banned from %s.  Exiting..", 
		 tcm_status.my_server ?
		 tcm_status.my_server : config_entries.server_name);
    tcm_log(L_ERR, "%s", "onservnotice Banned from server.  Exiting.");
    exit(-1);
    /* NOT REACHED */
    break;

  /* Possible Drone Flooder bill [bill@ummm.E] on irc.intranaut.com target:
     #clone */
  case DRONE:
    ++q;
    nick = q;

    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q++ = '\0';

    if ((p = strchr(q, ']')) == NULL)
      return;
    p+=5;

    if (get_user_host(&user, &host, q) != 1)
      return;

    from_server = p;
    if ((q = strchr(p, ' ')) == NULL)
      return;
    *q = '\0';
    q+=9;

    if (strcasecmp(from_server, tcm_status.my_server))
      return;

    send_to_all(FLAGS_WARN, "Possible drone flooder: %s!%s@%s target: %s",
                 nick, user, host, q);
    break;

  /* X-line Rejecting [Bill Jonus] [just because] user bill[bill@ummm.E] */
  case XLINEREJ:
    if ((nick = strrchr(q, ' ')) == NULL)
      return;
    ++nick;
    connect_flood_notice(nick, "X-Line rejections");
    break;

  /* Quarantined nick [bill] from user aa[bill@ummm.E] */
  case QUARANTINE:
    nick = q+2;
    connect_flood_notice(nick, "Quarantined nick");
    break;

  /* Invalid username: bill (!@$@&&&.com) */
  case INVALIDUH:
    nick = q+1;
    connect_flood_notice(nick, "Invalid user@host");
    break;

  /* Server ircd.flamed.net split from ircd.secsup.org */
  /* Server irc.intranaut.com being introduced by ircd.secsup.org */
  case SERVER:
    ++q;
    if (strstr(q, "split"))
    {
      nick = q;
      if ((q = strchr(nick, ' ')) == NULL)
        return;
      *q = '\0';
      user = q+12;
      send_to_all(FLAGS_SERVERS, "Server %s split from %s", nick, user);
    }
    else if (strstr(q, "being introduced"))
    {
      nick = q;
      if ((q = strchr(nick, ' ')) == NULL)
        return;
      *q = '\0';
      user = q+21;
      send_to_all(FLAGS_SERVERS, "Server %s being introduced by %s", nick, user);
    }
    break;

  case FAILEDOPER:
    nick = q+4;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    user = q+1;
    send_to_all(FLAGS_WARN, "*** Failed oper attempt by %s %s", nick, user);
    break;

  /* info requested by bill (bill@ummm.e) [irc.bill.eagan.mn.us] */
  case INFOREQUESTED:
    nick = q+1;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    user = q+2;
    if ((q = strchr(user, ')')) == NULL)
      return;
    *q = '\0';
    send_to_all(FLAGS_SPY, "[INFO requested by %s (%s)]", nick, user);
    break;

  /* No aconf found */
  case NOACONFFOUND:
    print_to_socket(connections[testlines.index].socket,
		    "%s does not have access",
		    testlines.umask);
    testlines.index = -1;
    memset((char *)&testlines.umask, 0, sizeof(testlines.umask));
    break;

  default:
    if ((p = strstr(message, "*** Notice -- ")))
      p += 14;
    else
      p = message;
    send_to_all(FLAGS_NOTICE, "Notice: %s", p);
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

  if (get_user_host(&user, &host, user_host) != 1)
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
  char user_host[MAX_USERHOST];
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

  if (get_user_host(&user, &host, seen_user_host) == 0)
    return;

  send_to_all(FLAGS_SPY, "[LINKS by %s (%s@%s)]",
	       nick_reported, user, host ); /* - zaph */

  snprintf(user_host, MAX_USERHOST, "%s@%s", user, host);

  for(i = 0; i < MAX_LINK_LOOKS; i++ )
    {
      if (link_look[i].user_host[0])
	{
	  if (!strcasecmp(link_look[i].user_host,user_host))
	    {
	      found_entry = YES;
	  
	      /* if its an old old entry, let it drop to 0, then start counting
	       * (this should be very unlikely case)
	       */

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
		  link_look[i].user_host[0] = '\0';
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
		  link_look[i].user_host[0] = '\0';
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
	  strlcpy(link_look[first_empty_entry].user_host,user_host,
		  MAX_USERHOST);
	  link_look[first_empty_entry].last_link_look = current_time;
          link_look[first_empty_entry].link_look_count = 1;
	}
    }
}

/*
 * cs_nick_flood
 *
 * inputs	- rest of notice from server
 * output	- NONE
 * side effects
 *
 * For clones CS uses [user@host] for nick flooding CS uses (user@host)
 * go figure.
 *
 */
static
void cs_nick_flood(char *snotice)
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

  if (get_user_host(&user, &host, user_host) == 0)
    return;

  send_to_all(FLAGS_WARN, "CS nick flood user_host = [%s@%s]", user, host);
  tcm_log(L_NORM, "%s", "CS nick flood user_host = [%s@%s]", user, host);
  handle_action(act_flood, nick_reported, user, host, 0, 0);
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

  if (get_user_host(&user, &host, user_host) == 0)
    return;

  send_to_all(FLAGS_WARN, "CS clones user_host = [%s]", user_host);
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
 */

static void
check_nick_flood(char *snotice)
{
  char *p;
  char *nick1;
  char *nick2;
  char *user_host;

  if ((p = strtok(snotice," ")) == NULL)	/* Throw away the "From" */
    return;

  if (strcasecmp(p,"From"))	/* This isn't an LT notice */
    {
      nick1 = p;	/* This _should_ be nick1 */

      if ((user_host = strtok(NULL," ")) == NULL)	/* (user@host) */
	return;

      if (*user_host == '(')
	user_host++;

      if ((p = strrchr(user_host,')')) != NULL)
	*p = '\0';

      if ((p = strtok(NULL," ")) == NULL)
	return;

      if (strcmp(p,"now") != 0 )
	return;

      if ((p = strtok(NULL," ")) == NULL)
	return;

      if (strcmp(p,"known") != 0 )
	return;

      if ((p = strtok(NULL," ")) == NULL)
	return;

      if (strcmp(p,"as") != 0)
	return;

      if ((nick2 = strtok(NULL," ")) == NULL)
	return;
      add_to_nick_change_table(user_host, nick2);
      update_nick(nick1, nick2);

      return;
    }

  if ((nick1 = strtok(NULL," ")) == NULL)
    return;

  if ((p = strtok(NULL," ")) == NULL)	/* Throw away the "to" */
    return;

  if ((nick2 = strtok(NULL," ")) == NULL)	/* This _should_ be nick2 */
    return;

  if ((user_host = strtok(NULL," ")) == NULL)	/* u@h  */
    return;

  if (*user_host == '[')
    user_host++;

  if ((p = strrchr(user_host,']')) != NULL)
    *p = '\0';

  add_to_nick_change_table(user_host,nick2);
  update_nick(nick1, nick2);
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
    link_look[i].user_host[0] = '\0';
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
add_to_nick_change_table(char *user_host,char *last_nick)
{
  char *user;
  char *host;
  int i;
  int found_empty_entry=-1;
  struct tm *tmrec;


  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
  {
    if (nick_changes[i].user_host[0])
    {
      time_t time_difference;
      int time_ticks;

      time_difference = current_time - nick_changes[i].last_nick_change;

      /* is it stale ? */
      if (time_difference >= NICK_CHANGE_T2_TIME)
      {
	nick_changes[i].user_host[0] = '\0';
	nick_changes[i].noticed = NO;
      }
      else
      {
	/* how many 10 second intervals do I have? */
	time_ticks = time_difference / NICK_CHANGE_T1_TIME;

	/* is it stale? */
	if (time_ticks >= nick_changes[i].nick_change_count)
	{
	  nick_changes[i].user_host[0] = '\0';
	  nick_changes[i].noticed = NO;
	}
	else
	{
	  /* just decrement 10 second units of nick changes */
	  nick_changes[i].nick_change_count -= time_ticks;

	  if ((strcasecmp(nick_changes[i].user_host,user_host)) == 0)
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
	    tmrec = localtime(&nick_changes[i].last_nick_change);

	    send_to_all(FLAGS_WARN,
		 "nick flood %s (%s) %d in %d seconds (%2.2d:%2.2d:%2.2d)",
			 nick_changes[i].user_host,
			 nick_changes[i].last_nick,
			 nick_changes[i].nick_change_count,
			 nick_changes[i].last_nick_change-
			 nick_changes[i].first_nick_change,
			 tmrec->tm_hour,
			 tmrec->tm_min,
			 tmrec->tm_sec);

	    
	    if ((user = strtok(user_host,"@")) == NULL)
	      return;
	    if ((host = strtok(NULL,"")) == NULL)
	      return;
		      
	    handle_action(act_flood, last_nick, user, host, 0, 0);
	    tcm_log(L_NORM,
		"nick flood %s (%s) %d in %d seconds (%02d/%02d/%d %2.2d:%2.2d:%2.2d)",
		nick_changes[i].user_host,
		nick_changes[i].last_nick,
		nick_changes[i].nick_change_count,
		nick_changes[i].last_nick_change-
		nick_changes[i].first_nick_change,
		tmrec->tm_mon+1,
		tmrec->tm_mday,
		tmrec->tm_year+1900,
		tmrec->tm_hour,
		tmrec->tm_min,
		tmrec->tm_sec);

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

  stat = *snotice;

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
  send_to_all(FLAGS_SPY, "[STATS %c requested by %s (%s)]",
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
      nick_changes[i].user_host[0] = '\0';
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
report_nick_flooders(int sock)
{
  int i;
  int reported_nick_flooder= NO;
  time_t time_difference;
  int time_ticks;

  assert(sock >= 0);

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
    {
      if (nick_changes[i].user_host[0])
        {
          time_difference = current_time - nick_changes[i].last_nick_change;

          /* is it stale ? */
          if( time_difference >= NICK_CHANGE_T2_TIME )
            {
              nick_changes[i].user_host[0] = '\0';
            }
          else
            {
              /* how many 10 second intervals do we have? */
              time_ticks = time_difference / NICK_CHANGE_T1_TIME;

              /* is it stale? */
              if(time_ticks >= nick_changes[i].nick_change_count)
                {
                  nick_changes[i].user_host[0] = '\0';
                }
              else
                {
                  /* just decrement 10 second units of nick changes */
                  nick_changes[i].nick_change_count -= time_ticks;
                  if( nick_changes[i].nick_change_count > 1 )
                    {
                      print_to_socket(sock,
                           "user: %s (%s) %d in %d",
                           nick_changes[i].user_host,
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
      print_to_socket(sock, "No nick flooders found" );
    }
}


/*
 * get_user_host
 *
 * inputs	- user_host pointer to string of form
 *		  (user@host) or
 *		  [user@host] or even plain old
 *		  user@host
 * outputs	- pointer to user
 *		- pointer to host
 * side effects	- input user_host is modified in place
 */

int
get_user_host(char **user_p, char **host_p, char *user_host)
{
  char *user = user_host;
  char *p;

  /*
   *  Lets try and get it right folks... [user@host] or (user@host)
   */

  if (*user == '[')
    {
      user++;
      if ((p = strchr(user, ']')) == NULL)
	return(0);
      *p = '\0';
    }
  else if (*user == '(')
    {
      user++;
      if ((p = strchr(user, ')')) == NULL)
	return(0);
      *p = '\0';
    }

  *user_p = user;

  if ((p = strchr(user, '@')) == NULL)
    return(0);

  *p = '\0';
  *host_p = p+1; 
  return (1);
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

  userinfo->user[0] = '\0';
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
          /* no [, no (, god knows what the seperator is */
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
	  strlcpy(userinfo->user, user, MAX_USER);
	  strlcpy(userinfo->host, host, MAX_HOST);
          return;
        }

      /* there *was* a [ as the seperator, uh points to it */

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
  strlcpy(userinfo->user, user, MAX_USER);
  strlcpy(userinfo->host, host, MAX_HOST);
}
