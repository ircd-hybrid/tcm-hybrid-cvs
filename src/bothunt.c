/* bothunt.c
 *
 * $Id: bothunt.c,v 1.130 2002/05/28 16:41:55 db Exp $
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
#include "commands.h"
#include "modules.h"
#include "tcm_io.h"
#include "parse.h"
#include "wingate.h"
#include "actions.h"
#include "match.h"
#include "hash.h"

#ifdef HAVE_REGEX_H
#include <regex.h>
#define REGCOMP_FLAGS REG_EXTENDED
#define REGEXEC_FLAGS 0
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned int) 0xffffffff)
#endif

static void check_nick_flood(char *snotice);
static void cs_nick_flood(char *snotice);
static void cs_clones(char *snotice);
static void link_look_notice(char *snotice);
static void connect_flood_notice(char *snotice);
static void add_to_nick_change_table(char *user_host, char *last_nick);
static void stats_notice(char *snotice);
static int  get_user_host(char **user_p, char **host_p, char *user_host);

struct s_testline testlines;
char   myclass[MAX_CLASS]; /* XXX */

struct nick_change_entry
{
  char user_host[MAX_USER+MAX_HOST];
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
  int  action;
};

struct msg_to_action msgs_to_mon[] = {
  {"Client connecting: ", CONNECT},
  {"Client exiting: ", EXITING},
  {"Unauthorized ", UNAUTHORIZED},
  {"Unauthorised client connection", UNAUTHORIZED},
  {"Nick change:", NICKCHANGE},
  {"Nick flooding detected by:", CS_NICKFLOODING},
  {"Rejecting ", CS_CLONES},
  {"Clonebot killed:",CS_CLONEBOT_KILLED},
  {"Idle time limit exceeded for ", IGNORE},
  {"LINKS ", LINK_LOOK},
  {"KLINE ", IGNORE},  
  {"STATS ", STATS},
  {"Got signal", SIGNAL},
  {"Nick collision on", IGNORE},
  {"Send message", IGNORE},
  {"Ghosted", IGNORE},
  {"connect failure",IGNORE},
  {"Invisible client count",IGNORE},
  {"Oper count off by",IGNORE},
  {"User count off by",IGNORE},
  {"Link with", LINKWITH},
  {"Received SQUIT", SQUITOF},
  {"motd requested by",MOTDREQ},
  {"Flooder", FLOODER},
  {"User", SPAMBOT},
  {"I-line mask", IGNORE},
  {"I-line is full", ILINEFULL},
  {"*** Banned: ", BANNED},
  {"*** You have been D-lined", BANNED},
  {"Possible Drone Flooder", DRONE},
  {"X-line Rejecting", XLINEREJ},
  {"Invalid username:", INVALIDUH},
  {"Server", SERVER},
  {"Failed OPER attempt", FAILEDOPER},
  {"info requested by", INFOREQUESTED},
  {"No aconf found", NOACONFFOUND},
  {"Quarantined nick", QUARANTINE},
  {(char *)NULL, INVALID}
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
  struct plus_c_info userinfo;
  char *class_ptr;	/* pointer to class number */
  int  is_oper;
  char *ip_ptr;
  char *right_bracket_ptr;

  if (!doingtrace)
    return;

  if (argv[3][0] == 'O')
    is_oper = YES;
  else
    is_oper = NO;

  /* /trace format the same now everywhere? */
  
  right_bracket_ptr = argv[6]+strlen(argv[6]);

  while(right_bracket_ptr != argv[6])
  {
    if ( *right_bracket_ptr == ')' )
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

  if (!strncmp(argv[5], mynick, strlen(mynick)))
  {
    snprintf(myclass, MAX_CLASS, "%s", argv[4]);
  }
  class_ptr = argv[4];

  chopuh(YES,argv[5],&userinfo);
  snprintf(userinfo.ip, MAX_IP, "%s", argv[6]+1);
  snprintf(userinfo.class, MAX_CLASS, "%s", class_ptr);

  /* XXX */
  userinfo.nick = argv[5]; /* XXX */
  adduserhost(&userinfo,YES,is_oper);
}

void
on_trace_class(int argc, char *argv[])
{
  if (doingtrace)
    doingtrace = NO;
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
  char *p;

  p = body;
  expand_args(body, MAX_BUFF-1, argc, argv);

/* No point if I am maxed out going any further */
  if (host_list_index == (MAXHOSTS - 1))
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

  strncpy(hostlist[host_list_index].user, user,
	  sizeof(hostlist[host_list_index].user));

  strncpy(hostlist[host_list_index].host, host,
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
  int  alpha, ok=NO;

  alpha = NO;

/* No point if I am maxed out going any further */
  if (host_list_index == (MAXHOSTS - 1))
    return;

  /* N.B. get_user_host modifies argv[6] */
  if (get_user_host(&user, &host, argv[6]) == 0)
    return;

  /* if client is exempt, mark it as such in the exemption list */

  for(;*user;user++)
  {
    switch(*user)
    {
    /* Check for flags that set some sort of exemption or protection from
     * something on the ircd side, and not flags that set some sort of
     * limitation.
     */
    case '^': /* K:/G: Protection (E:) */
    case '&': /* Can run a bot, obsolete in H7, should just add bot flags */
    case '>': /* Exempt from user limits (F:) */
    case '_': /* Exempt from G: - XXX should this be here? */
    case '<': /* Exempt from idle limitations - XXX should this be here? */
    case '=': /* Spoof...reasoning:  if they're spoofed, they're likely
               * trustworthy enough to be exempt from tcm's wrath
               */
      ok=YES;
      break;
      
    default:
      alpha = YES;
      break;
    }
    if (alpha)
      break;
  }

  if (ok)
  {
    strncpy(hostlist[host_list_index].user, 
	    user, sizeof(hostlist[host_list_index].user));

    strncpy(hostlist[host_list_index].host,
	    host, sizeof(hostlist[host_list_index].host));
    hostlist[host_list_index].type = 0xFFFFFFFF;

    host_list_index++;
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
on_server_notice(int argc, char *argv[])
{
  int i = -1, a, b, c = -1;
  int faction = -1;
  struct plus_c_info userinfo;
  char *from_server;
  /* XXX - Verify these down below */
  char *nick = NULL;
  char *user = NULL;
  char *host = NULL;
  char *target;
  char *p, *message;
  char *q = NULL;

  p = message = argv[argc-1];

  if (strncasecmp(p, "*** Notice -- ", 14) == 0)
    p+=14;

  for (i = 0; msgs_to_mon[i].msg_to_mon; i++)
  {
    if (strncmp(p,msgs_to_mon[i].msg_to_mon,
		strlen(msgs_to_mon[i].msg_to_mon)) == 0)
      break;
  }

  if (msgs_to_mon[i].msg_to_mon != NULL)
  {
    q = p+strlen(msgs_to_mon[i].msg_to_mon);
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
    send_to_all(SEND_WARN, "*** %s has just become an irc operator %s", 
	        message+14, q);
    return;
  }

  /* Kline notice requested by Toast */
  if (strstr(p, "added K-Line for"))
  {
    kline_report(p);
    return;
  }
  else if (strstr(p, "added temporary "))
  {
    kline_report(p);
    return;
  }
  else if (strstr(p, "has removed the "))
  {
    kline_report(p);
    return;
  }

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
    user = q+26;
    if ((q = strchr(user, '@')) == NULL)
      return;
    *q = '\0';
    host = q+1;
    if ((q = strchr(host, ']')) == NULL)
      return;
    *q = '\0';
    q+=3;
    if ((p = strrchr(q, ']')) == NULL)
      return;
    *p = '\0'; 
    send_to_all(SEND_KLINE_NOTICES,
                 "GLINE for %s@%s by %s [%s]: %s", user, host, nick, target, q);
    return;
  }
  else if ((q = strstr(p, "has triggered gline for ")) != NULL)
  {
    q += 24;
    get_user_host(&user, &host, q);
    if ((p = strchr(message+14, ' ')) != NULL)
      *p = '\0';
    p = host + strlen(host) + 1;
    send_to_all(SEND_KLINE_NOTICES,
		 "G-line for %s@%s triggered by %s: %s", user, host,
                 message+14, p);
    return;
  }

  if (strstr(p, "is rehashing"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q++ = '\0';
    if (strstr(q, " DNS"))
      send_to_all(SEND_SPY, "*** %s is rehashing DNS", nick);
    else
    {
      send_to_all(SEND_SPY, "*** %s is rehashing config file", nick);
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
    send_to_all(SEND_KLINE_NOTICES, "*** %s is clearing temp klines", nick);
    return;
  }
  else if (strstr(p, "clearing G-lines"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(SEND_KLINE_NOTICES, "*** %s is clearing g-lines", nick);
    return;
  }
  else if (strstr(p, "garbage collecting"))
  {
    nick = p;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    send_to_all(SEND_SPY, "*** %s is garbage collecting", nick);
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
    send_to_all(SEND_SPY, "*** %is is rehashing %s", nick, p);
    return;
  }

  if (strstr(p, "KILL message for"))
  {
    kill_add_report(p);
    return;
  }

  switch (faction)
  {
    char *user;
    char *host;

  /* Client connecting: bill (bill@ummm.E) [255.255.255.255] {1} */
  case CONNECT:
    if ((q = strchr(p, '(')) == NULL)
      return;
    *q = '\0';
    userinfo.user = q+1;
    *(q-1) = '\0';

    if ((q = strrchr(p, ' ')) == NULL)
      return;
    userinfo.nick = q+1;

    if ((q = strchr(userinfo.user, '@')) == NULL)
      return;
    *q++ = '\0';
    userinfo.host = q;

    if ((q = strchr(userinfo.host, ')')) == NULL)
      return;
    *q = '\0';
    q += 3;
    if ((p = strchr(q, ']')) == NULL)
      return;
    *p++ = '\0';
    strcpy((char *)&userinfo.ip, q);

    if ((q = strchr(p, '{')) == NULL)
      return;
    q++;
    if ((p = strchr(q, '}')) == NULL)
      return;
    *p = '\0';
    strcpy((char *)&userinfo.class, q);

    adduserhost(&userinfo, NO, NO);
    break;

  /* Client exiting: bill (bill@ummm.E) [e?] [255.255.255.255]*/
  case EXITING:
    chopuh(NO,q,&userinfo);
    removeuserhost(q,&userinfo);
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
    logfailure(p,NO);
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
    send_to_all(SEND_SERVERS, "Link with %s", q);
    break;

  /* Received SQUIT test.server from bill[bill@ummm.E] (this is a test) */
  case SQUITOF:
    ++q;
    if ((p = strchr(q, ' ')) == NULL)
      return;
    *p = '\0';
    p+=6;
    send_to_all(SEND_SERVERS, "SQUIT for %s from %s", q, p);
    break;

  /* motd requested by bill (bill@ummm.E) [irc.bill.eagan.mn.us] */
  case MOTDREQ:
    ++q;
    send_to_all(SEND_SPY, "[MOTD requested by %s]\n", q);
    break;

  case  IGNORE:
    break;

    /* send the unknown server message to opers who have requested
       they see them */
     /* WHAT?! -bill */

  /* Flooder bill [bill@ummm.E] on irc.intranaut.com target: #clone */ 
  case FLOODER:
    ++q;
    if ((p = strchr(q,' ')) == NULL)
      break;

    *p = '\0';
    p++;
    nick = q;

    user = p;
    if ((p = strchr(user,'[')) == NULL)
      break;
    p++;
    user = p;

    if ((p = strchr(user,'@')) == NULL)
      break;
    *p = '\0';
    p++;

    host = p;
    if ((p = strchr(host,']')) == NULL)
      break;
    *p = '\0';
    p++;

    if (*p != ' ')
      break;
    p++;

    /* p =should= be pointing at "on" */
    if ((p = strchr(p,' ')) == NULL)
      break;
    p++;

    from_server = p;
    if ((p = strchr(from_server,' ')) == NULL)
      break;
    *p = '\0';
    p++;

    if ((p = strstr(p, "target")) == NULL)
      break;

    target = p + 8;
    if (strcasecmp(config_entries.rserver_name,from_server) == 0)
    {
      send_to_all(SEND_WARN,
		   "*** Flooder %s (%s@%s) target: %s",
		   nick, user, host, target);
      handle_action(act_flood, (*user != '~'), nick, user, host, 0, 0);
    }

    break;

  /* User bill (bill@ummm.E) is a possible spambot */
  /* User bill (bill@ummm.E) trying to join #tcm is a possible spambot */
  case SPAMBOT:
    ++q;
    if ((p = strchr(q,' ')) == NULL)
      return;

    *p = '\0';
    nick = q;
    user = p+2;

    if ((p = strchr(user,'@')) == NULL)
      return;
    *p++ = '\0';

    host = p;
    if ((p = strchr(host,')')) == NULL)
      return;
    *p++ = '\0';

    if (strstr(p,"possible spambot") == NULL)
      return;

    handle_action(act_spambot, 0, nick, user, host, 0, 0);
    break;

  /* I-line is full for bill[bill@ummm.E] (127.0.0.1). */
  case ILINEFULL:
    connect_flood_notice(q);
    break;

  /* *** You have been D-lined */
  /* *** Banned: this is a test (2002/04/11 15.10) */
  case BANNED:
    send_to_all(SEND_ALL, "I am banned from %s.  Exiting..", 
		 config_entries.rserver_name[0] ?
		 config_entries.rserver_name : config_entries.server_name);
    tcm_log(L_ERR, "onservnotice Banned from server.  Exiting.");
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
    *q = '\0';
    user = q+2;
    if ((q = strchr(user, '@')) == NULL)
      return;
    *q++ = '\0';
    host = q;
    if ((q = strchr(host, ']')) == NULL)
      return;
    *q = '\0';
    q+=5;
    if ((p = strchr(q, ' ')) == NULL)
      return;
    *p = '\0';
    if (strcasecmp(q, config_entries.rserver_name) &&
        strcasecmp(q, config_entries.server_name))
      break;
    p+=9; 

    send_to_all(SEND_WARN, "Possible drone flooder: %s!%s@%s target: %s",
                 nick, user, host, p);
    break;

  /* X-line Rejecting [Bill Jonus] [just because] user bill[bill@ummm.E] */
  case XLINEREJ:
    if ((nick = strrchr(q, ' ')) == NULL)
      return;
    ++nick;

    if ((p = strchr(nick, '[')) == NULL)
      return;
    *p++ = '\0';
    user = p;

    if ((p = strrchr(user, ']')) == NULL)
      return;
    *p = '\0';
    c=-1;

    for (a=0;a<MAX_CONNECT_FAILS;++a)
    {
      if (connect_flood[a].user_host[0])
      {
	if (strcasecmp(connect_flood[a].user_host, user) == 0)
	{
	  if ((connect_flood[a].last_connect + MAX_CONNECT_TIME) < current_time)
	    connect_flood[a].connect_count = 0;

	  ++connect_flood[a].connect_count;
	  if ((p = strchr(user, '@')) == NULL)
	    break;
	  *p++ = '\0';
	  host = p;

	  if (connect_flood[a].connect_count >= MAX_CONNECT_FAILS)
	    {
	      if (user[0] == '~')
		b = NO;
	      else
		b = YES;
	      handle_action(act_cflood, (*user != '~'), nick, user, host, 0, "X-Line rejections");
	      connect_flood[a].user_host[0] = '\0';
	    }
	  else
	    connect_flood[a].last_connect = current_time;
	}
	else if ((connect_flood[a].last_connect + MAX_CONNECT_TIME) < current_time)
	  connect_flood[a].user_host[0] = '\0';
      }
      else c = a;
    }
    if (c >= 0)
    {
      if (strchr(user, '@'))
	snprintf(connect_flood[c].user_host,
		 MAX_USER+MAX_HOST, "%s", 
		 user);
      else
	snprintf(connect_flood[c].user_host,
		 MAX_USER+MAX_HOST, "%s@%s",
		 user, host);
      connect_flood[c].connect_count = 0;
      connect_flood[c].last_connect = current_time;
    }
    break;

  /* Quarantined nick [bill] from user aa[bill@ummm.E] */
  case QUARANTINE:
    nick = q+2;
    /* [ and ] are valid in nicks... find the FIRST space */
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    /* Now take us back to the ] */
    q--;
    *q = '\0';
    user = q+15;

    /* Find the RIGHTMOST ] */
    if ((p = strrchr(user, ']')) == NULL)
      return;
    *p = '\0';
    for (a=0;a<MAX_CONNECT_FAILS;++a)
    {
      if (connect_flood[a].user_host[0])
      {
        if (strcasecmp(connect_flood[a].user_host, user) == 0)
        {
          if ((connect_flood[a].last_connect + MAX_CONNECT_TIME) < current_time)
            connect_flood[a].connect_count = 0;
          ++connect_flood[a].connect_count;

          if ((p = strchr(user, '@')) == NULL)
            return;
          *p++ = '\0';
          host = p;

	  if (connect_flood[a].connect_count >= MAX_CONNECT_FAILS)
            {
	      handle_action(act_cflood, (*user != '~'), nick, user, host, 0, "Quarantined nick");
              connect_flood[a].user_host[0] = '\0';
            }
            else
              connect_flood[a].last_connect = current_time;
          return;
        }
        else if ((connect_flood[a].last_connect + MAX_CONNECT_TIME)
                 < current_time)
          connect_flood[a].user_host[0] = '\0';
      }
      else
        c = a;
    }
    if (c >= 0)
    {
      if (strchr(user, '@'))
        snprintf(connect_flood[c].user_host, MAX_USER + MAX_HOST, "%s", user);
      else
        snprintf(connect_flood[c].user_host, MAX_USER + MAX_HOST,
			"%s@%s", user, host);

      connect_flood[c].connect_count = 0;
      connect_flood[c].last_connect = current_time;
    }

  /* Invalid username: bill (!@$@&&&.com) */
  case INVALIDUH:
    nick = q+1;
    if ((p = strchr(nick, ' ')) == NULL)
      return;
    *p = '\0';
    user = p+2;
    if ((p = strchr(user, ')')) == NULL)
      return;
    *p++ = '\0';

    c = -1;
    for (a=0;a<MAX_CONNECT_FAILS;++a)
    {
      if (connect_flood[a].user_host[0])
      {
	if (!strcasecmp(user, connect_flood[a].user_host))
        {
	  if ((connect_flood[a].last_connect + MAX_CONNECT_TIME) < current_time)
	    connect_flood[a].connect_count = 0;

	  ++connect_flood[a].connect_count;
          if ((p = strchr(user, '@')) == NULL)
            return;
          *p++ = '\0';
          host = p;
	    if (connect_flood[a].connect_count >= MAX_CONNECT_FAILS)
	    {
	      handle_action(act_cflood, (*user != '~'), 
			    nick, user, host, 0, "Invalid user@host");
	      connect_flood[a].user_host[0] = '\0';
	    }
	}
	else if ((connect_flood[a].last_connect + MAX_CONNECT_TIME)
                 < current_time)
	  connect_flood[a].user_host[0] = '\0';
      }
      else
	c = a;
    }
    if (c >= 0)
    {
      if (strchr(user, '@'))
        snprintf(connect_flood[c].user_host, MAX_USER + MAX_HOST, "%s", user);
      else
        snprintf(connect_flood[c].user_host, MAX_USER + MAX_HOST,
                 "%s@%s", user, host);
      connect_flood[c].last_connect = current_time;
      connect_flood[c].connect_count = 0;
    }
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
      send_to_all(SEND_SERVERS, "Server %s split from %s", nick, user);
    }
    else if (strstr(q, "being introduced"))
    {
      nick = q;
      if ((q = strchr(nick, ' ')) == NULL)
        return;
      *q = '\0';
      user = q+21;
      send_to_all( SEND_SERVERS, "Server %s being introduced by %s", nick,
                   user);
    }
    break;

  case FAILEDOPER:
    nick = q+4;
    if ((q = strchr(nick, ' ')) == NULL)
      return;
    *q = '\0';
    user = q+1;
    send_to_all(SEND_WARN, "*** Failed oper attempt by %s %s", nick, user);
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
    send_to_all(SEND_SPY, "[INFO requested by %s (%s)]", nick, user);
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
    send_to_all(SEND_NOTICES, "Notice: %s", p);
    break;
  }
}


/*
 * check_reconnect_clones()
 *
 * inputs	- host
 * outputs	- none
 * side effects -
 */

void
check_reconnect_clones(char *host)
{
  int i;
  time_t now = time(NULL);

  if (host == NULL)  /* I don't know how this could happen.  ::shrug:: */
    return;

  for (i=0; i<RECONNECT_CLONE_TABLE_SIZE ; ++i)
  {
    if (!strcasecmp(reconnect_clone[i].host, host))
    {
      ++reconnect_clone[i].count;

      if ((reconnect_clone[i].count > CLONERECONCOUNT) &&
          (now - reconnect_clone[i].first <= CLONERECONFREQ))
      {
	handle_action(act_rclone, 0, "", "", host, 0, 0);
        reconnect_clone[i].host[0] = 0;
        reconnect_clone[i].count = 0;
        reconnect_clone[i].first = 0;
      }
      return;
    }
  }

  for (i=0; i < RECONNECT_CLONE_TABLE_SIZE; ++i)
  {
    if ((reconnect_clone[i].host[0]) &&
	(now - reconnect_clone[i].first > CLONERECONFREQ))
    {
      reconnect_clone[i].host[0] = 0;
      reconnect_clone[i].count = 0;
      reconnect_clone[i].first = 0;
    }
  }

  for (i=0 ; i < RECONNECT_CLONE_TABLE_SIZE ; ++i)
  {
    if (!reconnect_clone[i].host[0])
    {
      strncpy(reconnect_clone[i].host, host, MAX_HOST);
      reconnect_clone[i].host[MAX_HOST] = 0;
      reconnect_clone[i].first = now;
      reconnect_clone[i].count = 1;
      break;
    }
  }
}

/*
 * connect_flood_notice
 *
 * input	- pointer to notice
 * output	- none
 * side effects	-
 */
static void
connect_flood_notice(char *snotice)
{
  char *nick_reported;
  char *user_host;
  char user[MAX_USER+1];
  char host[MAX_HOST];
  char *ip;
  char *p;

  int first_empty_entry = -1;
  int found_entry = NO;
  int i, ident=YES;

  snotice +=5;

  p=nick_reported=snotice;
  while (*p != ' ' && *p != '[')
    ++p;
  user_host=p+1;
  *p = '\0';

  p=user_host;
  while (*p != ' ' && *p != ']')
    ++p;
  if (strlen(p) >= 4)
    ip=p+3;
  else return;
  *p = '\0';

  p=ip;
  if ((p = strchr(ip, ')')) == NULL)
    return;
  *p = '\0';

  p=user_host;
  while (*p != '@')
    ++p;
  *p='\0';
  snprintf(user, MAX_USER - 1, "%s", user_host);
  snprintf(host, MAX_HOST - 1, "%s", p+1);
  *p='@';

  for(i=0; i<MAX_CONNECT_FAILS; ++i)
    {
      if (connect_flood[i].user_host[0])
	{
	  if (strcasecmp(connect_flood[i].user_host, user_host) == 0)
	    {
	      found_entry = YES;

	      if ((connect_flood[i].last_connect + MAX_CONNECT_TIME)
		  < current_time)
		{
		  connect_flood[i].connect_count = 0;
		}

	      connect_flood[i].connect_count++;
	      if ((user[0] == '~') || (!strcmp(user, "unknown"))) 
		ident = 0;
	      else
		ident = 1;
	      if (connect_flood[i].connect_count >= MAX_CONNECT_FAILS)
		handle_action(act_cflood, ident, nick_reported, user, host, 0, 0);
	    }
	  else if ((connect_flood[i].last_connect + MAX_CONNECT_TIME)
		   < current_time) {
	    connect_flood[i].user_host[0] = '\0';
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
	  strncpy(connect_flood[first_empty_entry].user_host, user_host,
		  sizeof(connect_flood[first_empty_entry]));
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
  char user_host[MAX_HOST+MAX_NICK+2];
  char *seen_user_host;
  char *p;
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

  send_to_all(SEND_SPY, "[LINKS by %s (%s@%s)]",
	       nick_reported, user, host ); /* - zaph */

  snprintf(user_host, MAX_USER + MAX_HOST, "%s@%s", user, host);

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
				(*user != '~'),
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
	  strncpy(link_look[first_empty_entry].user_host,user_host,
		  MAX_USER+MAX_HOST);
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
  char *p;

  if ((nick_reported = strchr(snotice,' ')) == NULL)
    return;
  nick_reported++;

  if ((user_host = strchr(nick_reported,' ')) == NULL)
    return;

  if (get_user_host(&user, &host, user_host) == 0)
    return;

  send_to_all(SEND_WARN, "CS nick flood user_host = [%s@%s]", user, host);
  tcm_log(L_NORM, "CS nick flood user_host = [%s@%s]\n", user, host);
  handle_action(act_flood, (*user != '~'), nick_reported, user, host, 0, 0);
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
  int identd = YES;
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

  send_to_all(SEND_WARN, "CS clones user_host = [%s]", user_host);
  tcm_log(L_NORM, "CS clones = [%s]\n", user_host);

  if (*user == '~')
    {
      user++;
      identd = NO;
    }

  handle_action(act_clone, identd, "", user, host, 0, 0);
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
      add_to_nick_change_table(user_host,nick2);
      updateuserhost(nick1,nick2,user_host);

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

/* N.B.
 * hendrix's original code munges the user_host variable
 * so, add_to_nick_change must occur BEFORE
 * updateuserhost is called. grrrrrrrrrrrr
 * I hate order dependencies of calls.. but there you are.
 * This caused a bug in v0.1
 *
 */
  add_to_nick_change_table(user_host,nick2);
  updateuserhost(nick1,nick2,user_host);
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
	    (void)strncpy(nick_changes[i].last_nick,
			  last_nick,MAX_NICK);
	    nick_changes[i].nick_change_count++;
	  }

	  /* now, check for a nick flooder */
	  
	  if ((nick_changes[i].nick_change_count >=
	       NICK_CHANGE_MAX_COUNT)
	      && !nick_changes[i].noticed)
	  {
	    tmrec = localtime(&nick_changes[i].last_nick_change);

	    send_to_all(SEND_WARN,
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
		      
	    handle_action(act_flood, (*user_host != '~'), last_nick, user, host, 0, 0);
	    tcm_log(L_NORM,
		"nick flood %s (%s) %d in %d seconds (%02d/%02d/%d %2.2d:%2.2d:%2.2d)\n",
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
#ifdef STATS_P
  int i;
  int number_of_tcm_opers=0;
#endif
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
  {
    for (i=1;i<maxconns;++i)
    {
      /* ignore bad sockets */
      if (connections[i].socket == INVALID)
	continue;

      /* ignore invisible users/opers */
      if(has_umode(i, TYPE_INVS))
	continue;

      /* display opers */
      if(has_umode(i, TYPE_OPER))
      {
#ifdef HIDE_OPER_HOST
	notice(nick,
	       "%s - idle %lu\n",
	       connections[i].nick,
	       time(NULL) - connections[i].last_message_time );
#else 
	notice(nick,
	       "%s (%s@%s) idle %lu\n",
	       connections[i].nick,
	       connections[i].user,
	       connections[i].host,
	       time(NULL) - connections[i].last_message_time );
#endif
	number_of_tcm_opers++;
      }
    }
    notice(nick,"Number of tcm opers %d\n", number_of_tcm_opers);

    if (config_entries.statspmsg[0])
      notice(nick, config_entries.statspmsg);
  }
#endif

  send_to_all(SEND_SPY, "[STATS %c requested by %s (%s)]",
	       stat, nick, fulluh);
}

/*
 * reload_bothunt
 *
 * inputs	- none
 * output	- none
 * side effects	-
 */

void
reload_bothunt(void)
{
  if (!amianoper)
    oper();
}

void
init_bothunt(void)
{
  memset(&nick_changes,0,sizeof(nick_changes));
  memset(&reconnect_clone,0, sizeof(reconnect_clone));
  init_link_look_table();
  init_actions();

  if (connections[0].socket)
  {
    doingtrace = YES;
    print_to_server("TRACE");
  }
}

void
free_bothunt(void)
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
 *
 */

void 
report_nick_flooders(int sock)
{
  int i;
  int reported_nick_flooder= NO;
  time_t current_time;
  time_t time_difference;
  int time_ticks;

  if(sock < 0)
    return;

  current_time = time((time_t *)NULL);

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
                           "user: %s (%s) %d in %d\n",
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
      print_to_socket(sock, "No nick flooders found\n" );
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

static int
get_user_host(char **user_p, char **host_p, char *user_host)
{
  char *user = user_host;
  char *host;
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
