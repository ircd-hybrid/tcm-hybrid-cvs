/* bothunt.c
 *
 * $Id: bothunt.c,v 1.107 2002/05/26 05:48:04 db Exp $
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
#include "stdcmds.h"
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

static char* find_domain(char* domain );
static void  check_nick_flood(char *snotice );
static void  cs_nick_flood(char *snotice );
static void  cs_clones(char *snotice );
static void  link_look_notice(char *snotice );
static void  connect_flood_notice(char *snotice );
static void  add_to_nick_change_table(char *user_host, char *last_nick );
static void  adduserhost(struct plus_c_info *, int, int);
static void  removeuserhost(char *, struct plus_c_info *);
static void  updateuserhost(char *nick1, char *nick2, char *userhost);
static void  updatehash(struct hashrec**,char *,char *,char *); 
static void  stats_notice(char *snotice);
static int hash_func(char *string);
static void addtohash(struct hashrec *table[],char *key,struct userentry *item);
static int removefromhash(struct hashrec *table[], char *key, char *hostmatch,
			  char *usermatch, char *nickmatch);
static void check_host_clones(char *);
#ifdef VIRTUAL
static void check_virtual_host_clones(char *);
#endif
static void check_reconnect_clones(char *);

struct s_testline testlines;
char myclass[100]; /* XXX */

int act_cflood, act_vclone, act_flood, act_link,
  act_bot, act_spambot, act_clone, act_rclone;

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

struct banned_info glines[MAXBANS];

/*
 * find_banned_host
 *
 * inputs	- user
 * 		- hostname
 * output	- return index of user@host found in glines, or -1
 *		  if not found
 * side effects	-
 */
static int
find_banned_host(char *user, char *host)
{
  int i;

  for (i=0; i < MAXBANS; i++)
  {
    if (glines[i].user[0] != '\0' && glines[i].host[0] != '\0')
    {
      if (!strcmp(user, glines[i].user) && !strcmp(host, glines[i].host))
        return i;
    }
  }
  /* There was no match above, so we KNOW match == NO - Hwy */
  return -1;
}

/*
 * remove_gline
 *
 * inputs	- user
 * 		- hostname
 * output	- none
 * side effects	-
 */
static void
remove_gline(char *user, char *host)
{
  int i;
  if ((i = find_banned_host(user, host)) == -1)
    return;

  glines[i].user[0] = '\0';
  glines[i].host[0] = '\0';
  glines[i].next = NULL;
  glines[i].when = 0;
}

/*
 * gline_request
 *
 * inputs	- username
 *		- hostname
 *		- reason 
 *		- who did the gline
 *		- when 
 * output	- ??
 * side effects	-
 */
static int
gline_request(char *user, char *host, char *reason, char *who)
{
  int i;

  if (find_banned_host(user, host) != -1) return 0;

  /* find an empty spot for this new request */
  for (i=0; i < MAXBANS; i++)
    if (glines[i].user[0] == '\0')
      break;

  strlcpy(glines[i].user, user, MAX_USER);
  strlcpy(glines[i].host, host, MAX_HOST);
  strlcpy(glines[i].reason, reason, MAX_REASON);
  strlcpy(glines[i].who, who, MAX_WHO);
  glines[i].when = current_time;

  return 1;
}

/*
 * _ontraceuser()
 * 
 * inputs	- traceline from server
 * output	- NONE
 * side effects	- user is added to hash tables
 * 
 */

void
_ontraceuser(int connnum, int argc, char *argv[])
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
    snprintf(myclass, sizeof(myclass), "%s", argv[4]);
  }
  class_ptr = argv[4];

  chopuh(YES,argv[5],&userinfo);
  snprintf(userinfo.ip, sizeof(userinfo.ip), "%s", argv[6]+1);
  snprintf(userinfo.class, sizeof(userinfo.class) - 1, "%s", class_ptr);

  /* XXX */
  userinfo.nick = argv[5]; /* XXX */
  adduserhost(&userinfo,YES,is_oper);
}

void
_ontraceclass(int connnum, int argc, char *argv[])
{
  if (doingtrace)
  {
    doingtrace = NO;
    join(config_entries.defchannel, config_entries.defchannel_key);
    set_modes(config_entries.defchannel, config_entries.defchannel_mode,
              config_entries.defchannel_key);
  }
}

/* 
 * on_stats_o()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- user list of tcm is built up from stats O of tcm server
 * 
 *   Some servers have some "interesting" O lines... lets
 * try and filter some of the worst ones out.. I have seen 
 * *@* used in a servers O line.. (I will not say which, to protect
 * the guilty)
 */

void
on_stats_o(int connnum, int argc, char *argv[])
{
  char *user_at_host;
  char *user;
  char *host;
  char *nick;
  char *p;		/* pointer used to scan for valid O line */

/* No point if I am maxed out going any further */
  if ( user_list_index == (MAXUSERS - 1))
    return;

  user = user_at_host = argv[4];
  nick = argv[6];

  if ((p = strchr(user_at_host, '@')) != NULL)
    {
      *p++ = '\0';
      host = p;
    }
  else
    {
      user = "*";
      host = p;
    }

  /* Don't allow *@* or user@* O: lines */
  if (strcmp(host, "*") == 0)
    return;

  /*
   * If this user is already loaded due to userlist.load
   * don't load them again.
   */

  if (!isoper(user,host) )
  {
    strncpy(userlist[user_list_index].user, user, 
	    sizeof(userlist[user_list_index].user));

    strncpy(userlist[user_list_index].host, host, 
	    sizeof(userlist[user_list_index].host));

    strncpy(userlist[user_list_index].usernick, nick, 
	    sizeof(userlist[user_list_index].usernick));

    userlist[user_list_index].password[0] = '\0';
    userlist[user_list_index].type = 0;
    user_list_index++;
  }
  /*
   * Really should exempt opers, as spoof I-Lines arent shown
   * on stats I
   */ 
  strcpy(hostlist[host_list_index].user, user);
  strcpy(hostlist[host_list_index].host, host);
  hostlist[host_list_index].type = 0xFFFFFFFF;
  ++host_list_index;
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
on_stats_e(int connnum, int argc, char *argv[])
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
on_stats_i(int connnum, int argc, char *argv[])
{
  char *user;
  char *host;
  char *p;
  int  alpha, ok=NO;

  alpha = NO;

/* No point if I am maxed out going any further */
  if (host_list_index == (MAXHOSTS - 1))
    return;

  if ((p = strchr(argv[6],'@')) == NULL)	/* find the u@h part */
    return;

  *p = '\0';				/* blast the '@' */
  host = p+1;				/* host part is past the '@' */

  p = user = argv[6];

  /* if client is exempt, mark it as such in the exemption list */

  for(;*p;p++)
  {
    switch(*p)
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

  user = p;

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
 * onservnotice()
 *
 * inputs	- message from server
 * output	- NONE
 * side effects	-
 */
void
onservnotice(int connnum, int argc, char *argv[])
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
    gline_request(user, host, q, nick);
    send_to_all(SEND_KLINE_NOTICES,
                 "GLINE for %s@%s by %s [%s]: %s", user, host, nick, target, q);
    return;
  }
  else if (strstr(p, "has triggered gline for "))
  {
    q = strstr(p, "has triggered gline for ");
    q += 25;
    if ((p = strchr(q, '@')) == NULL)
      return;
    *p++ = '\0';
    user = q;
    host = p;
    if ((p = strchr(host, ']')) == NULL)
      return;
    *p = '\0';
    p += 3;
    if ((q = strrchr(p, ']')) == NULL)
      return;
    *q = '\0';
    if ((q = strchr(message+14, ' ')) == NULL)
      return;
    *q = '\0';
     
    send_to_all(SEND_KLINE_NOTICES,
		 "G-line for %s@%s triggered by %s: %s", user, host,
                 message+14, p);
    remove_gline(user, host);
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
    for (a=0;a<MAXBANS;++a)
    {
      xfree(glines[i].user);
      xfree(glines[i].host);
      glines[i].when = 0;
    }
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
    log_problem("onservnotice", "Banned from server.  Exiting.");
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
		 sizeof(connect_flood[c].user_host), "%s", 
		 user);
      else
	snprintf(connect_flood[c].user_host,
		 sizeof(connect_flood[c].user_host), "%s@%s",
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
        snprintf(connect_flood[c].user_host, sizeof(connect_flood[c].user_host),
                 "%s", user);
      else
        snprintf(connect_flood[c].user_host, sizeof(connect_flood[c].user_host),
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
        snprintf(connect_flood[c].user_host, sizeof(connect_flood[c].user_host),
                 "%s", user);
      else
        snprintf(connect_flood[c].user_host, sizeof(connect_flood[c].user_host),
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
 * _onctcp
 * inputs	- nick
 *		- user@host
 * 		- text argument
 * output	- NONE
 *
 */

void
_onctcp(int connnum, int argc, char *argv[])
{
  char *hold, *nick, *port, *a;
  char *msg=argv[3]+1;
  char dccbuff[MAX_BUFF];

  nick = argv[0];
  hold = nick + strlen(nick) + 1;
  if (strncasecmp(msg,"PING",4) == 0)
  {
    notice(nick, "%s", argv[3]);
    return;
  }
  else if (strncasecmp(msg,"VERSION",7) == 0)
  {
    notice(nick,"\001VERSION %s(%s)\001",VERSION,SERIALNUM);
  }
  else if (strncasecmp(msg, "DCC CHAT", 8) == 0)
  {
    /* the -6 saves room for the :port */
    snprintf(dccbuff, sizeof(dccbuff)-7, "#%s", argv[3]+15);
    if ((port = strrchr(argv[3], ' ')) == NULL)
    {
      notice(nick, "Invalid port specified for DCC CHAT.  Not funny.");
      return;
    }
    ++port;
    if ((a = strrchr(port, '\001')) != NULL)
      *a = '\0';

    strcat(dccbuff, ":");
    strcat(dccbuff, port);

    if (accept_dcc_connection(dccbuff, nick, hold) < 0)
    {
      notice(nick, "\001DCC REJECT CHAT chat\001");
      notice(nick,"DCC CHAT connection failed");
      return;
    }
  }
}

/*
 * hash_func()
 *
 * inputs	- string to hash
 * output	- hash function result
 * side effects	-
 */
int
hash_func(char *string)
{
  int i;

  i = *(string++);
  if (*string)
    i |= (*(string++) << 8);
    if (*string)
      i |= (*(string++) << 16);
      if (*string)
        i |= (*string << 24);
  return (i % HASHTABLESIZE);
}

/*
 * addtohash
 * 
 * inputs	- pointer to hashtable to add to
 *		- pointer to key being used for hash
 *		- pointer to item being added to hash
 * output	- NONE
 * side effects	- adds an entry to given hash table
 */
void
addtohash(struct hashrec *table[],char *key,struct userentry *item)
{
  int ind;
  struct hashrec *newhashrec;

  ind = hash_func(key);
  newhashrec = (struct hashrec *)xmalloc(sizeof(struct hashrec));

  newhashrec->info = item;
  newhashrec->collision = table[ind];
  table[ind] = newhashrec;
}


/*
 * removefromhash()
 *
 * inputs	- pointer to hashtable to remove entry from
 *		- pointer to key being used for hash
 *		- pointer to hostname to match before removal
 *		- pointer to username to match before removal
 *		- pointer to nickname to match before removal
 * output	- NONE
 * side effects	- adds an entry to given hash table
 */

static int
removefromhash(struct hashrec *table[],
		    char *key,
		    char *hostmatch,
		    char *usermatch,
		    char *nickmatch)
{
  int ind;
  struct hashrec *find, *prev;

  ind = hash_func(key);
  find = table[ind];
  prev = NULL;

  while (find)
  {
    if ((!hostmatch || !strcmp(find->info->host,hostmatch)) &&
	(!usermatch || !strcmp(find->info->user,usermatch)) &&
	(!nickmatch || !strcmp(find->info->nick,nickmatch)))
    {
      if (prev)
	prev->collision = find->collision;
      else
	table[ind] = find->collision;

      if (find->info->link_count > 0)
      {
	find->info->link_count--;
	if (find->info->link_count == 0)
	  {
            xfree(find->info);
	  }
      }

      xfree(find);
      return 1;		/* Found the item */
    }
    prev = find;
    find = find->collision;
  }
  return (0);
}

/*
 * updateuserhost()
 * 
 * inputs -	- original nick
 *		- new nick
 * 		- user@host of nick
 * output	- NONE
 * side effects - A user has changed nicks. update the nick
 *	          as seen by the hosttable. This way, list command
 *	          will show the updated nick.
 */

static void
updateuserhost(char *nick1,char *nick2,char *userhost)
{
  char *host;

  if ((host = strchr(userhost,'@')) == NULL)
    return;

  *host = '\0';
  host++;
  
  updatehash(hosttable,host,nick1,nick2);
}

/*
 * updatehash
 *
 * inputs	- has table to update
 *		- key to use
 *		- nick1, nick2 nick changes
 * output	- NONE
 * side effects	- user entry nick is updated if found
 */

static void
updatehash(struct hashrec *table[],
		       char *key,char *nick1,char *nick2)
{
  struct hashrec *find;

  for (find = table[hash_func(key)]; find; find = find->collision)
  {
    if (strcmp(find->info->nick,nick1) == 0)
    {
      strncpy(find->info->nick,nick2,MAX_NICK);
    }
  }
}

/*
 * removeuserhost()
 * 
 * inputs	- nick
 * 		- pointer to struct plus_c_info
 * output	- NONE
 * side effects	- 
 */

static void
removeuserhost(char *nick, struct plus_c_info *userinfo)
{
#ifdef VIRTUAL
  int  found_dots;
  char ip_class_c[MAX_IP];
  char *p;
#endif
  char *domain;

  /* Determine the domain name */
  domain = find_domain(userinfo->host);

  if (!removefromhash(hosttable,
		      userinfo->host,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(hosttable,
			userinfo->host,
			userinfo->host,
			userinfo->user,NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,"*** Error removing %s!%s@%s from host table!\n",
		nick,
		userinfo->user,
		userinfo->host);
      }
    }

  if (!removefromhash(domaintable,
		      domain,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(domaintable,
			domain,
			userinfo->host,
			userinfo->user,
			NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,"*** Error removing %s!%s@%s from domain table!\n",
		nick,
		userinfo->user,
		userinfo->host);
      }
    }

  if (!removefromhash(usertable,
		      userinfo->user,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(usertable,
			userinfo->user,
			userinfo->host,
			userinfo->user,
			NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,"*** Error removing %s!%s@%s from user table!\n",
		nick,
		userinfo->user,
		userinfo->host);
      }
    }

#ifdef VIRTUAL
  /* well, no such thing as a class c , but it will do */
  if (userinfo->ip)
    strcpy(ip_class_c,userinfo->ip);
  else
    ip_class_c[0] = '\0';

  p = ip_class_c;
  found_dots = 0;
  while(*p)
  {
    if (*p == '.')
      found_dots++;

    if (found_dots == 3)
    {
      *p = '\0';
      break;
    }
    p++;
  }

  if (config_entries.debug && outfile)
  {
    fprintf(outfile,
	    "about to removefromhash ip_class_c = [%s]\n", ip_class_c);
    fprintf(outfile,
	    "userinfo->host [%s] userinfo->user [%s] nick [%s]\n",
	    userinfo->host,userinfo->user,nick);
  }

  if (!removefromhash(iptable,
		      ip_class_c,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(iptable,
			ip_class_c,
			userinfo->host,
			userinfo->user,
			NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,
		"*** Error removing %s!%s@%s [%s] from iptable table!\n",
		nick,
		userinfo->user,
		userinfo->host,
		ip_class_c);
      }
    }
#endif
}


/*
 * adduserhost()
 * 
 * inputs	- pointer to struct plus_c_info
 * 		- from a trace YES or NO
 * 		- is this user an oper YES or NO
 * output	- NONE
 * side effects	-
 * 
 * These days, its better to show host IP's as class C
 */

static void
adduserhost(struct plus_c_info *userinfo, int fromtrace, int is_oper)
{
  struct userentry *newuser;
  char *domain;
#ifdef VIRTUAL
  int  found_dots;
  char *p;
#endif

  if (!doingtrace)
    user_signon(userinfo);

  newuser = (struct userentry *)xmalloc(sizeof(struct userentry));

  strlcpy(newuser->nick, userinfo->nick, MAX_NICK);
  strlcpy(newuser->user,userinfo->user,MAX_NICK);
  strlcpy(newuser->host,userinfo->host,MAX_HOST);
  if (userinfo->ip[0])
    strlcpy(newuser->ip_host,userinfo->ip,MAX_IP);
  else
    strcpy(newuser->ip_host,"0.0.0.0");

#ifdef VIRTUAL
  /* well, no such thing as a class c , but it will do */
  if (userinfo->ip)
    strcpy(newuser->ip_class_c,userinfo->ip);
  else
    newuser->ip_class_c[0] = '\0';

  p = newuser->ip_class_c;

  found_dots = 0;
  while(*p)
  {
    if (*p == '.')
      found_dots++;
    
    if (found_dots == 3)
    {
      *p = '\0';
      break;
    }
    p++;
  }
#endif

  newuser->connecttime = (fromtrace ? 0 : time(NULL));
  newuser->reporttime = 0;

#ifdef VIRTUAL
  if (newuser->ip_class_c[0])
    newuser->link_count = 4;
  else
    newuser->link_count = 3;
#else
  newuser->link_count = 3;
#endif

  newuser->isoper = is_oper;
  strcpy(newuser->class, userinfo->class);

  /* Determine the domain name */
  domain = find_domain(userinfo->host);

  strncpy(newuser->domain,domain,MAX_DOMAIN);
  newuser->domain[MAX_DOMAIN-1] = '\0';

  /* Add it to the hash tables */
  addtohash(usertable, userinfo->user, newuser);
  addtohash(hosttable, userinfo->host, newuser);
  addtohash(domaintable, domain, newuser);

#ifdef VIRTUAL
  if (newuser->ip_class_c[0])
    addtohash(iptable, newuser->ip_class_c, newuser);
#endif

  /* Clonebot check */
  if (!fromtrace)
  {
    check_host_clones(userinfo->host);
#ifdef VIRTUAL
    check_virtual_host_clones(newuser->ip_class_c);
#endif
    check_reconnect_clones(userinfo->host);
  }
}

/*
 * find_domain
 *
 * inputs	- pointer to hostname found
 * output	- pointer to domain
 * side effects	- none
 *
 * return pointer to domain found from host name
 */
static char*
find_domain(char* host)
{
  char *ip_domain;
  char *found_domain;
  int  found_dots=0;
  int  two_letter_tld=NO;
  int is_legal_ip = YES;
  static char iphold[MAX_IP+1];
  int i = 0;
 
  ip_domain = host;

  if (isdigit((int) *ip_domain))
  {
    while (*ip_domain)
    {
      iphold[i++] = *ip_domain;
      if (*ip_domain == '.')
	found_dots++;
      else if (!isdigit((int) *ip_domain))
	{
	  is_legal_ip = NO;
	  break;
	}

      if (found_dots == 3 )
	break;

      ip_domain++;

      if ( i > (MAX_IP-2))
      {
	is_legal_ip = NO;
	break;
      }
    }
    iphold[i++] = '*';
    iphold[i] = '\0';
    ip_domain = iphold;
  }

  if ((found_dots != 3) || !is_legal_ip)
  {
    found_domain = host + (strlen(host) - 1);

    /* find tld "com" "net" "org" or two letter domain i.e. "ca" */
    while (found_domain != host)
    {
      if (*found_domain == '.')
      {
	if (found_domain[3] == '\0')
	{
	  two_letter_tld = YES;
	}
	found_domain--;
	break;
      }
      found_domain--;
    }

    while (found_domain != host)
    {
      if (*found_domain == '.')
      {
	if (!two_letter_tld)
	{
	  found_domain++;
	}
	else
	{
	  found_domain--;
	}
	break;
      }
      found_domain--;
    }

    if (two_letter_tld)
    {
      while (found_domain != host)
      {
	if (*found_domain == '.')
	{
	  found_domain++;
	  break;
	}
	found_domain--;
      }
    }
    return(found_domain);
  }
  else
  {
    return(ip_domain);
  }
}

/*
 * check_reconnect_clones()
 *
 * inputs	- host
 * outputs	- none
 * side effects -
 */

static void
check_reconnect_clones(char *host)
{
  int i;
  time_t now = time(NULL);

  if (host == NULL)  /* I don't know how this could happen.  ::shrug:: */
    return;

  for ( i=0; i<RECONNECT_CLONE_TABLE_SIZE ; ++i )
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

  for ( i=0 ; i < RECONNECT_CLONE_TABLE_SIZE ; ++i )
  {
    if (!reconnect_clone[i].host[0])
    {
      strncpy(reconnect_clone[i].host, host, sizeof(reconnect_clone[i].host));
      reconnect_clone[i].host[MAX_HOST] = 0;
      reconnect_clone[i].first = now;
      reconnect_clone[i].count = 1;
      break;
    }
  }
}

/*
 * check_host_clones()
 * 
 * inputs	- host
 * output	- none
 * side effects	- 
 */

static void
check_host_clones(char *host)
{
  struct hashrec *find;
  int clonecount = 0;
  int reportedclones = 0;
  char *last_user="";
  int current_identd;
  int different;
  time_t now, lastreport, oldest;
  char notice1[MAX_BUFF];
  char notice0[MAX_BUFF];
  struct tm *tmrec;
  int ind;

  notice1[0] = '\0';
  notice0[0] = '\0';
  oldest = now = time(NULL);
  lastreport = 0;
  ind = hash_func(host);

  for (find = hosttable[ind]; find; find = find->collision)
  {
    if ((strcmp(find->info->host,host) == 0)&&
	(now - find->info->connecttime < CLONECONNECTFREQ + 1))
    {
      if (find->info->reporttime > 0)
      {
	++reportedclones;
	if (lastreport < find->info->reporttime)
	  lastreport = find->info->reporttime;
      }
      else
      {
	++clonecount;
	if (find->info->connecttime < oldest)
	  oldest = find->info->connecttime;
      }
    }
  }

  if ((reportedclones == 0 && clonecount < CLONECONNECTCOUNT) ||
      now - lastreport < 10)
    return;

  if (reportedclones)
  {
    report(SEND_WARN,
	   CHANNEL_REPORT_CLONES,
	   "%d more possible clones (%d total) from %s:\n",
	   clonecount, clonecount+reportedclones, host);

    log("%d more possible clones (%d total) from %s:\n",
	clonecount, clonecount+reportedclones, host);
  }
  else
  {
    report(SEND_WARN,
	   CHANNEL_REPORT_CLONES,
	   "Possible clones from %s detected: %d connects in %d seconds\n",
	   host, clonecount, now - oldest);

    log("Possible clones from %s detected: %d connects in %d seconds\n",
	host, clonecount, now - oldest);
  }

  for( find = hosttable[ind],clonecount = 0; find; find = find->collision)
  {
    if ((strcmp(find->info->host,host) == 0) &&
	(now - find->info->connecttime < CLONECONNECTFREQ + 1) &&
	find->info->reporttime == 0)
    {
      ++clonecount;
      tmrec = localtime(&find->info->connecttime);

      if (clonecount == 1)
      {
	(void)snprintf(notice1,sizeof(notice1) - 1,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)\n",
		       find->info->nick, 
		       find->info->user,
		       find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }
      else
      {
        memset((char *)&notice0, 0, sizeof(notice0));
	(void)snprintf(notice0,sizeof(notice0) - 1,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)\n",
		       find->info->nick,
		       find->info->user,
		       find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }

      current_identd = YES;
      different = NO;

      if (clonecount == 1)
	last_user = find->info->user;
      else if (clonecount == 2)
      {
	char *current_user;
	
	if ( *last_user == '~' )
	{
	  last_user++;
	}

	current_user = find->info->user;
	if ( *current_user != '~' )
	  current_identd = YES;
	else
	  ++current_user;

	if (strcmp(last_user,current_user) && current_identd)
	  different = YES;

	handle_action(act_clone, current_identd, 
		      find->info->nick, find->info->user,
		      find->info->host, find->info->ip_host, 0);
      }

      find->info->reporttime = now;
      if (clonecount == 2)
      {
        if (notice1[0])
        {
  	  report(SEND_WARN, CHANNEL_REPORT_CLONES, "%s", notice1);
	  log("%s", notice1);
        }
	/* I haven't figured out why all these are nessecary, but I know they are */
	if (notice0[0])
        {
          report(SEND_WARN, CHANNEL_REPORT_CLONES, "%s", notice0);
  	  log("%s", notice0);
        }
      }
      else if (clonecount < 5)
      {
        if (notice0[0])
        {
	  report(SEND_WARN, CHANNEL_REPORT_CLONES, "%s", notice0);
	  log("%s", notice0);
        }
      }
      else if (clonecount == 5)
      {
        if (notice0[0])
        {
	  send_to_all( SEND_WARN, "%s", notice0);
	  log("  [etc.]\n");
        }
      }
    }
  }
}

/*
 * check_virtual_host_clones()
 * 
 * inputs	- "class c" ip as string
 * output	- none
 * side effects	- 
 *
 */
#ifdef VIRTUAL
static void
check_virtual_host_clones(char *ip_class_c)
{
  struct hashrec *find;
  int clonecount = 0;
  int reportedclones = 0;
  time_t now, lastreport, oldest;
  char notice1[MAX_BUFF];
  char notice0[MAX_BUFF];
  char user[MAX_USER];
  struct tm *tmrec;
  int ind, different=NO, ident=YES;

  oldest = now = time(NULL);
  lastreport = 0;

  ind = hash_func(ip_class_c);

  for (find = iptable[ind]; find; find = find->collision)
    {
      if (!strcmp(find->info->ip_class_c,ip_class_c) &&
	  (now - find->info->connecttime < CLONECONNECTFREQ + 1))
      {
	if (find->info->reporttime > 0)
	  {
	    ++reportedclones;
	    if (lastreport < find->info->reporttime)
	      lastreport = find->info->reporttime;
	  }
	else
	  {
	    ++clonecount;
	    if (find->info->connecttime < oldest)
	      oldest = find->info->connecttime;
	  }
       }
    }

  if (((reportedclones == 0) && (clonecount < CLONECONNECTCOUNT)) ||
      (now - lastreport < 10))
    return;

  if (reportedclones)
    {
      report(SEND_WARN,
	     CHANNEL_REPORT_VCLONES,
	     "%d more possible virtual host clones (%d total) from %s.*:\n",
	     clonecount, clonecount+reportedclones, ip_class_c);

      log("%d more possible virtual host clones (%d total) from %s.*:\n",
	  clonecount, clonecount+reportedclones, ip_class_c);
    }
  else
    {
      report(SEND_WARN,
	     CHANNEL_REPORT_VCLONES,
	     "Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	     ip_class_c, clonecount, now - oldest);

      log("Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	    ip_class_c, clonecount, now - oldest);
    }

  clonecount = 0;

  memset(&user, 0, sizeof(user));
  for ( find = iptable[ind]; find; find = find->collision )
    {
      if (!strcmp(find->info->ip_class_c,ip_class_c) &&
	  (now - find->info->connecttime < CLONECONNECTFREQ + 1) &&
	  find->info->reporttime == 0)
	{
	  ++clonecount;
	  tmrec = localtime(&find->info->connecttime);

          if (user[0] == '\0')
	    snprintf(user, sizeof(user), "%s", find->info->user);

          if (strcasecmp(user, find->info->user))
	    different=YES;

          if (find->info->user[0] == '~')
	    ident = NO;
          else
	    ident = YES;

	  if (clonecount == 1)
	    {
	      (void)snprintf(notice1,sizeof(notice1) - 1,
                            "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)\n",
			    find->info->nick,
			    find->info->user,
			    find->info->host,
			    find->info->ip_host,
			    tmrec->tm_hour,
			    tmrec->tm_min,
			    tmrec->tm_sec);
	    }
          else
	    {
	      (void)snprintf(notice0,sizeof(notice0) - 1,
                            "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)\n",
			    find->info->nick,
			    find->info->user,
			    find->info->host,
			    find->info->ip_host,
			    tmrec->tm_hour,
			    tmrec->tm_min,
			    tmrec->tm_sec);
	    }

          /* apparently we do not want to kline
	   * *@some.net.block.0/24 if the idents differ
	   *
	   * we do, however, if they differ w/o ident
	   * (ie ~clone1, ~clone2, ~clone3)        
	   */
          if ((different == NO && ident == YES) || (ident == NO))
            {
	      handle_action(act_vclone, ident,
			    find->info->nick, find->info->user,
			    find->info->ip_host, find->info->ip_host, 0);
            }

	  find->info->reporttime = now;
	  if (clonecount == 1)
	    ;
	  else if (clonecount == 2)
	    {
	      report(SEND_WARN, CHANNEL_REPORT_VCLONES, "%s", notice1);
	      log("%s", notice1);

	      report(SEND_WARN, CHANNEL_REPORT_VCLONES, "%s", notice0);
	      log("%s", notice0);
	    }
	  else if (clonecount < 5)
	    {
	      report(SEND_WARN, CHANNEL_REPORT_VCLONES, "%s", notice0);
	      log("%s", notice0);
	    }
	  else if (clonecount == 5)
	    {
	      send_to_all(SEND_WARN, "%s", notice0);
	      log("  [etc.]\n");
	    }
	}

    }
}
#endif

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
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  char *ip;
  char *p;

  int first_empty_entry = -1;
  int found_entry = NO;
  int i, ident=YES;

  snotice +=5;

  p=nick_reported=snotice;
  while (*p != ' ' && *p != '[') ++p;
  user_host=p+1;
  *p = '\0';

  p=user_host;
  while (*p != ' ' && *p != ']') ++p;
  if (strlen(p) >= 4) ip=p+3;
  else return;
  *p = '\0';

  p=ip;
  if (!(p = strchr(ip, ')'))) return;
  *p = '\0';

  p=user_host;
  while (*p != '@') ++p;
  *p='\0';
  snprintf(user, sizeof(user) - 1, "%s", user_host);
  snprintf(host, sizeof(host) - 1, "%s", p+1);
  *p='@';

  for(i=0;i<MAX_CONNECT_FAILS;++i)
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
  char user_host[MAX_HOST+MAX_NICK+2];
  char *user, *host;
  char *p;
  int first_empty_entry = -1;
  int found_entry = NO;
  int i;

  p = strstr(snotice,"requested by");

  if (!p)
    return;

  nick_reported = p + 13;

  if ((p = strchr(nick_reported,' ')))
    *p = '\0';
  else
    return;
  p++;

  user = p;
/*
 *  Lets try and get it right folks... [user@host] or (user@host)
 */

  if (*user == '[')
  {
    user++;
    if ((p = strchr(user, ']')) == NULL)
      return;
    *p = '\0';
  }
  else if (*user == '(')
  {
    user++;
    if ((p = strchr(user, ')')) == NULL)
      return;
    *p = '\0';
  }
  else
    return;

  if ((p = strchr(user, '@')) == NULL)
    return;

  *p = '\0';
  host = p+1; 

  send_to_all(SEND_SPY, "[LINKS by %s (%s@%s)]",
	       nick_reported, user, host ); /* - zaph */

  snprintf(user_host, sizeof(user_host), "%s@%s", user, host);

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
		  handle_action(act_link, (*user != '~'), nick_reported, user, host, 0, 0);
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

  if ( !(nick_reported = strtok(snotice," ")) )
    return;

  if ( !(user_host = strtok(NULL," ")) )
    return;

/*
 * Lets try and get it right folks... [user@host] or (user@host)
 */

  if (*user_host == '[')
    {
      user_host++;
      if ( (p = strrchr(user_host,']')) )
	*p = '\0';
    }
  else if (*user_host == '(')
    {
      user_host++;
      if ( (p = strrchr(user_host,')')) )
	*p = '\0';
    }

  send_to_all(SEND_WARN, "CS nick flood user_host = [%s]", user_host);

  log("CS nick flood user_host = [%s]\n", user_host);


  if ( !(user = strtok(user_host,"@")) )
    return;

  if ( !(host = strtok(NULL,"")) )
    return;

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
  char *user;
  char *host;
  char *p;
  char *user_host;

  if ( !(strtok(snotice," ") == NULL) )
    return;

  if ( !(user_host = strtok(NULL," ")) )
    return;

  if (*user_host == '[')
    {
      user_host++;
      if ( (p = strrchr(user_host,']')) )
	*p = '\0';
    }
  else if (*user_host == '(')
    {
      user_host++;
      if ( (p = strrchr(user_host,')')) )
	*p = '\0';
    }

  send_to_all(SEND_WARN, "CS clones user_host = [%s]", user_host);
  log("CS clones = [%s]\n", user_host);

  user = user_host;

  if (*user == '~')
    {
      user++;
      identd = NO;
    }

  if ( !(host = strchr(user_host,'@')) )
    return;

  *host = '\0';
  host++;
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

  if ( !(p = strtok(snotice," ")) )	/* Throw away the "From" */
    return;

  if (strcasecmp(p,"From"))	/* This isn't an LT notice */
    {
      nick1 = p;	/* This _should_ be nick1 */

      if ( !(user_host = strtok(NULL," ")) )	/* (user@host) */
	return;

      if (*user_host == '(')
	user_host++;

      if ( (p = strrchr(user_host,')')) )
	*p = '\0';

      if ( !(p = strtok(NULL," ")) )
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
	    log(
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

  if ( (p = strchr(fulluh, ')' )) )
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
      if (connections[i].type & (TYPE_INVS|TYPE_INVM))
	continue;

      /* display opers */
      if (connections[i].type & TYPE_OPER)
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

void _reload_bothunt(int connnum, int argc, char *argv[])
{
 if (!amianoper) oper();
}

/*
 * m_gline
 *
 * inputs	- connection number
 *		- argc count
 *		- arguments
 * output	- none
 * side effects -
 */
void
m_gline(int connnum, int argc, char *argv[])
{
  int i;
  int number_nonwilds=0;
  char *p;
  char *hostname;
  char gline_reason[MAX_REASON];

  if (!(connections[connnum].type & TYPE_GLINE))
  {
    print_to_socket(connections[connnum].socket,
		    "You do not have %s access", argv[0]);
    return;
  }

  if (argc == 1)
  {
    for (i=0; i < MAXBANS; i++)
    { 
      if (glines[i].user[0] && glines[i].host[0])
        print_to_socket(connections[connnum].socket, "%d) %s@%s :%s -- %s",
			i+1,
			glines[i].user,
			glines[i].host, glines[i].reason, glines[i].who);
    }
    return;
  }

  if (argc == 2)
  {
    if ((i = atoi(argv[1])) && glines[i-1].user[0] && glines[i-1].host[0])
    {
      print_to_server("GLINE %s@%s :%s", glines[i-1].user, glines[i-1].host,
             (glines[i-1].reason[0] == '\0') ? "No reason" : glines[i-1].reason);
      return;
    }
    else
    {
      for (p = argv[1], number_nonwilds=0; *p; p++)
	{
	  if (*p != '?' && *p != '*')
	    number_nonwilds++;
	}

      if (number_nonwilds < 4)
      {
        print_to_socket(connections[connnum].socket,
        "Please include at least 4 non-wildcard characters in the user@host\n");
        return;
      }

      if ((hostname = strchr(argv[1], '@')) == NULL)
      {
        print_to_socket(connections[connnum].socket,
             "Please include a \'@\' in the user@host\n");
        return;
      }
      *hostname++ = '\0';
      print_to_server("GLINE %s@%s :No reason", argv[1], hostname);
      return;
    }
  }
  else if (argc >= 3)
  {
    if ((i = atoi(argv[1])) && glines[i-1].user[0] && glines[i-1].host[0])
    {
      expand_args(gline_reason, MAX_REASON, argc-2, argv+2);
      print_to_server("GLINE %s@%s :%s", glines[i-1].user, glines[i-1].host,
             (*gline_reason == ':') ? gline_reason+1 : gline_reason);
      return;
    }
    else
    {
      for(p = argv[1], number_nonwilds=0; *p; p++)
        {
          if (*p != '?' && *p != '*')
            number_nonwilds++;
        }

      if (number_nonwilds < 4)
      {
        print_to_socket(connections[connnum].socket,
      "Please include at least 4 non-wildcard characters with the user@host\n");
        return;
      }
      if ((hostname = strchr(argv[1], '@')) == NULL)
      {
        print_to_socket(connections[connnum].socket,
             "Please include a \'@\' with the user@host\n");
        return;
      }

      expand_args(gline_reason, MAX_REASON, argc, argv);
      print_to_server("GLINE %s@%s :%s", argv[1], hostname, gline_reason);
      return;
    }
  }
}

struct dcc_command gline_msgtab = {
 "gline", NULL, {m_unregistered, m_gline, m_gline}
};

void init_bothunt(void)
{
  memset(&usertable,0,sizeof(usertable));
  memset(&hosttable,0,sizeof(usertable));
  memset(&domaintable,0,sizeof(usertable));
#ifdef VIRTUAL
  memset(&iptable,0,sizeof(iptable));
#endif
  memset(&nick_changes,0,sizeof(nick_changes));
  memset(&reconnect_clone,0, sizeof(reconnect_clone));
  init_link_look_table();
  act_cflood = add_action("cflood");
  set_action_strip(act_cflood, HS_CFLOOD);
  set_action_reason(act_cflood, REASON_CFLOOD);

  act_vclone = add_action("vclone");
  set_action_strip(act_vclone, HS_VCLONE);
  set_action_reason(act_vclone, REASON_VCLONE);

  act_flood = add_action("flood");
  set_action_strip(act_flood, HS_FLOOD);
  set_action_reason(act_flood, REASON_FLOOD);

  act_link = add_action("link");
  set_action_strip(act_link, HS_LINK);
  set_action_reason(act_link, REASON_LINK);

  act_bot = add_action("bot");
  set_action_strip(act_bot, HS_BOT);
  set_action_reason(act_bot, REASON_BOT);

  act_spambot = add_action("spambot");
  set_action_strip(act_spambot, HS_SPAMBOT);
  set_action_reason(act_spambot, REASON_SPAMBOT);

  act_clone = add_action("clone");
  set_action_strip(act_clone, HS_CLONE);
  set_action_reason(act_clone, REASON_CLONE);

  act_rclone = add_action("rclone");
  set_action_strip(act_rclone, HS_RCLONE);
  set_action_reason(act_rclone, REASON_RCLONE);

  if (connections[0].socket)
  {
    doingtrace = YES;
    print_to_server("TRACE");
  }
}

