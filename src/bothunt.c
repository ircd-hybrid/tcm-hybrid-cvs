/*
** This code below is UGLY as sin and is not commented.  I would NOT use
** it for the basis of anything real, as it is the worst example of data
** structure misuse and abuse that I have ever SEEN much less written.
** If you're looking for how to implement hash tables, don't look here.
** If I had $100 for every time I looped thru every bucket of the hash
** tables to process a user command, I could retire.  Any way, it may be
** inefficient as hell when handling user commands, but it's fast and
** much cleaner when handling the server notice traffic.  Since the server
** notice traffic should outweigh commands to the bot by - oh like - 100
** to 1 or more, I didn't care too much about inefficiencies and ugliness
** in the stuff that processes user commands... I just wanted to throw it
** together quickly.
*/
/* (Hendrix original comments) */

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "config.h"
#include "tcm.h"
#include "stdcmds.h"
#include "serverif.h"
#include "bothunt.h"
#include "userlist.h"
#include "token.h"
#include "logging.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"
#include "modules.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: bothunt.c,v 1.9 2001/10/10 00:03:44 bill Exp $";
char *_version="20012009";

static char* find_domain( char* domain );
static void  check_nick_flood( char *server_notice );
static void  cs_nick_flood( char *server_notice );
static void  cs_clones( char *server_notice );
static void  link_look_notice( char *server_notice );
static void  connect_flood_notice( char *server_notice );
static void  add_to_nick_change_table( char *user_host, char *last_nick );
static void  bot_reject( char *text );
static void  adduserhost( char *, struct plus_c_info *, int, int);
static void  removeuserhost( char *, struct plus_c_info *);
static void  updateuserhost( char *nick1, char *nick2, char *userhost);
static void  updatehash(struct hashrec**,char *,char *,char *); 
static void  stats_notice(char *server_notice);
static char to_find_k_user[MAX_USER];
static char to_find_k_host[MAX_HOST];
static int hash_func(char *string);
static void addtohash(struct hashrec *table[],char *key,struct userentry *item);
static char removefromhash(struct hashrec *table[], char *key, char *hostmatch,
                    char *usermatch, char *nickmatch);

#define R_CLONE		0x001
#define R_VCLONE	0x002
#define R_FLOOD         0x008
#define R_LINK          0x010
#define R_BOT		0x020
#define R_CTCP          0x100
#define R_SPAMBOT       0x400
#define R_CFLOOD        0x800

char *msgs_to_mon[] = {
  "Client connecting: ", 
  "Client exiting: ",
  "Unauthorized ",
  "Rejecting clonebot:",		/* CSr notice */
  "Too many connections from ",
  "Nick change:",
  "Nick flooding detected by:",		/* CSr notice */
  "Rejecting ",
  "Clonebot killed:",			/* CSr notice */
  "Idle time limit exceeded for ",	/* CSr notice */
  "LINKS ",
  "KLINE ",	/* Just a place holder */
  "STATS ",	/* look at stats ... */
  "JohBot alarm activated:",
  "EggDrop signon alarm activated:",

  "Nick collision on",		/* IGNORE1 ignore these */
  "Send message",		/* IGNORE2 ignore these */
  "Ghosted",			/* IGNORE3 ignore these */
  "connect failure",		/* IGNORE4 ignore these */
  "Invisible client count",	/* IGNORE5 ignore these */
  "Oper count off by",		/* IGNORE6 ignore these */
  "User count off by",		/* IGNORE7 ignore these */
  "Link with",
  "Write error to",
  "Received SQUIT",
  "motd requested by",
  "Flooder",
  "User",
  "I-line mask",
  "I-line is full",
  (char *)NULL
};	


extern struct connection connections[];
extern int doingtrace;

#define LINK_LOOK_TABLE_SIZE 10

struct link_look_entry
{
  char user_host[MAX_USER+MAX_HOST+2];
  int  link_look_count;
  time_t last_link_look;
};

struct link_look_entry link_look[LINK_LOOK_TABLE_SIZE];

#define CONNECT_FLOOD_TABLE_SIZE 30

struct connect_flood_entry
{
  char user_host[MAX_USER+MAX_HOST+2];
  char ip[18];
  int  connect_count;
  time_t last_connect;
};

struct connect_flood_entry connect_flood[CONNECT_FLOOD_TABLE_SIZE];

/*
 * _ontraceuser()
 * 
 * inputs	- traceline from server
 * output	- NONE
 * side effects	- user is added to hash tables
 * 
 * 
 * texas went and modified the output of /trace in their irc server
 * so that it appears as "nick [user@host]" _ontraceuser promptly
 * threw out the "[user@host]" part.. *sigh* I've changed the code
 * here to check for a '[' right after a space, and not blow away
 * the "[user@host]" part. - Dianora
 * 
 * This is moot now, as no one now runs this variant...
 */

void _ontraceuser(int connnum, int argc, char *argv[])
{
  char *nuh;
  struct plus_c_info userinfo;
  char *userhost;
  char *p;		/* used to clean up trailing garbage */
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

  while((*ip_ptr != ')') && *ip_ptr) ++ip_ptr;
  if (*ip_ptr == ')') *ip_ptr = '\0';

  class_ptr = argv[4];
  chopuh(YES,argv[5],&userinfo);
  snprintf(userinfo.ip, sizeof(userinfo.ip), "%s", argv[6]+1);
  snprintf(userinfo.class, sizeof(userinfo.class) - 1, "%s", class_ptr);

  adduserhost(argv[5],&userinfo,YES,is_oper);
}

void _ontraceclass(int connnum, int argc, char *argv[])
{
  if (doingtrace)
    {
      doingtrace = NO;
      toserv("JOIN %s %s\n", config_entries.defchannel, config_entries.defchannel_key);
    }
}

/* 
 * on_stats_o()
 *
 * inputs		- body of server message
 * output		- none
 * side effects	- user list of tcm is built up from stats O of tcm server
 * 
 *   Some servers have some "interesting" O lines... lets
 * try and filter some of the worst ones out.. I have seen 
 * *@* used in a servers O line.. (I will not say which, to protect
 * the guilty)
 *
 *
 * Thinking about this.. I think perhaps this code should just go away..
 * Certainly, if you have REMOTE_KLINE etc. defined... You will need
 * to add users to userlist.cf anyway.
 * 
 */

void on_stats_o(int connnum, int argc, char *argv[])
{
  char body[MAX_BUFF];
  char *user_at_host;
  char *user;
  char *host;
  char *nick;
  int non_lame_user_o;	/* If its not a wildcarded user O line... */
  int non_lame_host_o;	/* If its not a wildcarded host O line... */
  char *p;		/* pointer used to scan for valid O line */

  for (non_lame_user_o=0;non_lame_user_o<argc;++non_lame_user_o)
    {
      strncat(body, argv[non_lame_user_o], sizeof(body)-strlen(body));
      strncat(body, " ", sizeof(body)-strlen(body));
    }
  if (body[strlen(body)-1] == ' ') body[strlen(body)-1] = '\0';

/* No point if I am maxed out going any further */
  if ( user_list_index == (MAXUSERS - 1))
    return;

  user_at_host = p = argv[4];
  nick = argv[6];
  non_lame_user_o = NO;

  while(*p)
    {
      if (*p == '@')	/* Found the first part of "...@" ? */
	break;

      if (*p != '*')	/* A non wild card found in the username? */
	non_lame_user_o = YES;	/* GOOD a non lame user O line */
      /* can't just break. I am using this loop to find the '@' too */

      p++;
    }
  
  if (!non_lame_user_o)	/* LAME O line ignore it */
    return;

  p++;			/* Skip the '@' */
  non_lame_host_o = NO;

  while(*p)
    {
      if (*p != '*')	/* A non wild card found in the hostname? */
	non_lame_host_o = YES;	/* GOOD a non lame host O line */
      p++;
    }

  if (!non_lame_host_o)
    return;
  user = user_at_host;

  if ((p = strchr(user_at_host,'@')) )
    {
      *p = '\0';
       p++;
       host = p;
    }
  else
    {
      user = "*";
      host = user_at_host;
    }

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
      userlist[user_list_index].type = TYPE_OPER;
      user_list_index++;
    }
}

/* 
 * on_stats_e()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- exception list of tcm is built up from stats E of server
 * 
 */

void on_stats_e(int connnum, int argc, char *argv[])
{
  char *user;
  char *host;
  char body[MAX_BUFF];
  int i;

  for (i=0;i<argc;++i)
    {
      strncat(body, argv[i], sizeof(body)-strlen(body));
      strncat(body, " ", sizeof(body)-strlen(body));
    }
  if (body[strlen(body)-1] == ' ') body[strlen(body)-1] = '\0';

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

void on_stats_i(int connnum, int argc, char *argv[])
{
  char *user;
  char *host;
  char *p;
  char body[MAX_BUFF];
  int  alpha, ok=NO;

  for (alpha = 0; alpha < argc; ++alpha)
    {
      strncat(body, argv[alpha], sizeof(body)-strlen(body));
      strncat(body, " ", sizeof(body)-strlen(body));
    }
  if (body[strlen(body)-1] == ' ' ) body[strlen(body)-1] = '\0';
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
        case '<':case '-':case '$':
	case '%':case '^':case '&':case '>':
	case '_':
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
      strncpy(hostlist[host_list_index].user, user,sizeof(hostlist[host_list_index].user));
      strncpy(hostlist[host_list_index].host, host, sizeof(hostlist[host_list_index].host));
      host_list_index++;
    }
}

/* 
 * on_stats_k()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- 
 * 
 */

void on_stats_k(int connnum, int argc, char *argv[])
{
  char *user;
  char *host;
  char *p;
  char body[MAX_BUFF];
  int i;

  for (i = 0; i < argc; ++i)
    {
      strncat(body, argv[i], sizeof(body)-strlen(body));
      strncat(body, " ", sizeof(body)-strlen(body));
    }
  if (body[strlen(body)-1] == ' ') body[strlen(body)-1] = '\0';

  if ((p = strchr(body,' ')) == NULL)
    return;
  p++;

  host = p;
  if ((p = strchr(host,' ')) == NULL)
    return;
  *p++ = '\0';

  if ((p = strchr(p, ' ')) == NULL)
    return;
  p++;

  user = p;
  if ((p = strchr(user, ' ')) == NULL)
    return;
  *p++ = '\0';
}

/*
 * onservnotice()
 *
 * inputs	- message from server
 * output	- NONE
 * side effects	-
 */

void onservnotice(int connnum, int argc, char *argv[])
{
  int i = -1;
  struct plus_c_info userinfo;
  char *from_server;
  char *nick;
  char *user;
  char *host;
  char *target;
  char *p, *q, *r;
  char message[1024];
#ifdef DEBUGMODE
  placed;
#endif

  memset((void *)&message, 0, sizeof(message));

  for (i=3;i<argc;++i)
    {
      strcat((char *)&message, argv[i]);
      strcat((char *)&message, " ");
    }

  if (message[strlen(message)-1] == ' ') message[strlen(message)-1] = '\0';

  if (message[0] == ':')
    p = message+1;
  else
    p = message;

  if (!strncasecmp(p, "*** Notice -- ", 14)) p+=14;
  i = -1;

  while (msgs_to_mon[++i])
    {
      if (!strncmp(p,msgs_to_mon[i],strlen(msgs_to_mon[i])))
        break;
    }

  if (msgs_to_mon[i]) q = p+strlen(msgs_to_mon[i]);
  if (strstr(p, "closed the connection") &&
      !strncmp(p, "Server", 6)) 
    {
      sendtoalldcc(SEND_LINK_ONLY, "Lost server: %s\n", argv[2]);
      return;
    }

  /* Kline notice requested by Toast */
  if (strstr(p, "added K-Line for"))
    {
      kline_add_report(p);
      return;
    }

  if (strstr(p, "KILL message for"))
    {
      kill_add_report(p);
      return;
    }

  switch (i)
    {
    case CONNECT:
      chopuh(NO,q,&userinfo);
      adduserhost(q,&userinfo,NO,NO);
      break;

    case EXITING:
      chopuh(NO,q,&userinfo);
      removeuserhost(q,&userinfo);
      break;

    case UNAUTHORIZED:
      p = strstr(q,"from");
      if (p)
        {
	  q = p+5;
	}
      logfailure(q,0);
      break;
    case REJECTING:
      bot_reject(q);
      break;
    case TOOMANY:
      logfailure(q,0);
      break;
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
    case LINK_LOOK:
      link_look_notice(q);
      break;
    case STATS:
      stats_notice(q);
      break;
    case JOHBOT:
#ifdef DEBUGMODE
      placed;
#endif
#ifdef BOT_WARN
      bot_report_kline(q,"johbot");
#endif
      break;
    case EGGDROP:
#ifdef DEBUGMODE
      placed;
#endif
#ifdef BOT_WARN
      bot_report_kline(q,"eggdrop");
#endif
      break;
    case LINKWITH:
      ++q;
      
      sendtoalldcc(SEND_LINK_ONLY, "Link with %s\n", q);
      break;

    case WRITEERR:
      sendtoalldcc(SEND_LINK_ONLY, "Write error to %s, closing link.\n", argv[2]);
      break;

    case SQUITOF:
      sendtoalldcc(SEND_LINK_ONLY, "SQUIT for %s from %s\n", argv[1], argv[4]);
      break;

    case MOTDREQ:
      ++q;
      sendtoalldcc(SEND_MOTD_ONLY, "[MOTD requested by %s]\n", q);
      break;

    case  IGNORE1:case IGNORE2:case IGNORE3:case IGNORE4:case IGNORE5:
    case  IGNORE6:case IGNORE7:
#ifdef DEBUGMODE
      placed;
#endif
      break;

      /* send the unknown server message to opers who have requested
	 they see them */

    case FLOODER:
      ++q;
      if (!(p = strchr(q,' ')))
	break;

      *p = '\0';
      p++;
      nick = q;

      user = p;
      if (!(p = strchr(user,'[')))
	break;
      p++;
      user = p;

      if (!(p = strchr(user,'@')))
	break;
      *p = '\0';
      p++;

      host = p;
      if (!(p = strchr(host,']')))
	break;
      *p = '\0';
      p++;

      if (*p != ' ')
	break;
      p++;

      /* p =should= be pointing at "on" */
      if (!(p = strchr(p,' ')))
	break;
      p++;

      from_server = p;
      if (!(p = strchr(from_server,' ')))
	break;
      *p = '\0';
      p++;

      p = strstr(p, "target");

      target = p + 8;

      if (!strcasecmp(target,nick))
	{
	  sendtoalldcc(SEND_WARN_ONLY,
		       "User CTCP Flooding themselves, strange %s!%s@%s\n",
		       nick, user, host);
	  break;
	}

      if (!strcasecmp(config_entries.rserver_name,from_server))
	{
	  if (*user == '~')
	    user++;
	  suggest_action(get_action_type("ctcp"), nick, user, host, NO, YES);
	}

      break;

    case SPAMBOT:
      ++q;
      if (!(p = strchr(q,' ')))
	break;

      *p = '\0';
      p++;
      nick = q;

      user = p;
      if (!(p = strchr(user,'(')))
	break;
      p++;
      user = p;

      if (!(p = strchr(user,'@')))
	break;
      *p = '\0';
      p++;

      host = p;
      if (!(p = strchr(host,')')))
	break;
      *p = '\0';
      p++;

      if (!strstr(p,"possible spambot"))
	break;

      suggest_action(get_action_type("spambot"), nick, user, host, NO, YES);
      break;

    case ILINEFULL:
      connect_flood_notice(q);
      break;

    default:
      sendtoalldcc(SEND_OPERS_NOTICES_ONLY, "%s", message);
      break;
    }
}

/*
** makeconn()
**   Makes another connection
*/

char makeconn(char *hostport,char *nick,char *userhost)
{
  int  i;               /* index variable */
  char *p;              /* scratch pointer used for parsing */
  char *type;
  char *user;
  char *host;
#ifdef DEBUGMODE
  placed;
#endif

  for (i=1; i<MAXDCCCONNS+1; ++i)
    if (connections[i].socket == INVALID)
      {
        if (maxconns < i+1)
          maxconns = i+1;
        break;
      }

  if (i > MAXDCCCONNS)
    return 0;

  if ( (p = strchr(userhost,'@')) )
    {
      user = userhost;
      *p = '\0';
      p++;
      host = p;
    }
  else
    {
      host = userhost;
      user = "*";
    }

  if ( (p = strchr(host,' ')) )
    *p = '\0';

  if (config_entries.opers_only)
    {
      if (!isoper(user,host))
        {
          notice(nick,"You aren't an oper");
          return 0;
        }
    }
  connections[i].socket = bindsocket(hostport);

  if (connections[i].socket == INVALID)
    return 0;
  connections[i].set_modes = 0;

  connections[i].buffer = (char *)malloc(BUFFERSIZE);
  bzero(connections[i].buffer, BUFFERSIZE);
  if (!connections[i].buffer)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in makeconn\n");
      gracefuldie(0, __FILE__, __LINE__);
    }

  connections[i].buffend = connections[i].buffer;
  strncpy(connections[i].nick,nick,MAX_NICK-1);
  connections[i].nick[MAX_NICK-1] = '\0';


  strncpy(connections[i].user,user,MAX_USER-1);
  connections[i].user[MAX_USER-1] = '\0';
  strncpy(connections[i].host,host,MAX_HOST-1);
  connections[i].host[MAX_HOST-1] = '\0';
  connections[i].type = 0;
  connections[i].type |= isoper(user,host);

  if ( !(connections[i].type & TYPE_OPER) &&
      isbanned(user,host)) /* allow opers on */
    {
      prnt(connections[i].socket,
           "Sorry, you are banned.\n");
      (void)close(connections[i].socket);
      connections[i].socket = INVALID;
      connections[i].nick[0] = '\0';
      connections[i].registered_nick[0] = '\0';
      connections[i].user[0] = '\0';
      connections[i].type = 0;
      (void)free(connections[i].buffer);
      return 0;
    }

  connections[i].last_message_time = time(NULL);

  print_motd(connections[i].socket);

  if (config_entries.autopilot)
    prnt(connections[i].socket,"autopilot is ON\n");
  else
    prnt(connections[i].socket,"autopilot is OFF\n");

  type = "User";
  if (connections[i].type & TYPE_OPER)
    type = "Oper";
  if (connections[i].type & TYPE_TCM)
    type = "Tcm";

  report(SEND_ALL_USERS,
         CHANNEL_REPORT_ROUTINE,
         "%s %s (%s@%s) has connected\n",
         type,
         connections[i].nick,
         connections[i].user,
         connections[i].host);

  prnt(connections[i].socket,
       "Connected.  Send '.help' for commands.\n");
  return 1;
}

/*
 * _onctcp
 * inputs	- nick
 *		- user@host
 * 		- text argument
 * output	- NONE
 *
 */

void _onctcp(int connnum, int argc, char *argv[])
{
  char *hold, *nick;
  char *msg=argv[3]+2;
  char dccbuff[DCCBUFF_SIZE];
  int i;

  nick = argv[0] + 1;
  if ((hold = strchr(argv[0], '!'))) *hold = '\0';
  else return;
  ++hold;
  if (dccbuff[0] != '\0') memset(&dccbuff, 0, sizeof(dccbuff));

  if (!strncasecmp(msg,"PING",4))
    {
      for (i=4;i<argc;++i)
        {
          strncat(dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
          strncat(dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
        }
      if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
      if (dccbuff[strlen(dccbuff)-1] == '\001') dccbuff[strlen(dccbuff)-1] = '\0';
      notice(nick, "\001PING %s\001\n", dccbuff);
      return;
    }
  else if (!strncasecmp(msg,"VERSION",7))
    {
      notice(nick,"\001VERSION %s(%s)\001",VERSION,SERIALNUM);
    }
  else if (!strcasecmp(argv[3],":\001DCC") && !strcasecmp(argv[4], "CHAT"))
    {
      snprintf(dccbuff, sizeof(dccbuff), "#%s", argv[6]);
      if (atoi(argv[7]) < 1024)
        {
          notice(nick, "Invalid port specified for DCC CHAT. Not funny.");
          return;
        }
      strcat(dccbuff, ":");
      strcat(dccbuff, argv[7]);
      if (!makeconn(dccbuff, nick, hold))
        {
	  notice(nick,"DCC CHAT connection failed");
	  return;
	}
    }
}

int hash_func(char *string)
{
  long i;

  i = *(string++);
  if (*string)
    i |= (*(string++) << 8);
    if (*string)
      i |= (*(string++) << 16);
      if (*string)
        i |= (*string << 24);
  return i % HASHTABLESIZE;
}

/*
 */

void addtohash(struct hashrec *table[],char *key,struct userentry *item)
{
  int ind;
  struct hashrec *newhashrec;

  ind = hash_func(key);
  newhashrec = (struct hashrec *)malloc(sizeof(struct hashrec));
  if ( !newhashrec )
    {
      prnt(connections[0].socket,"Ran out of memory in addtohash\n");
      sendtoalldcc(SEND_ALL_USERS,"Ran out of memory in addtohash\n");
      gracefuldie(0, __FILE__, __LINE__);
    }

  newhashrec->info = item;
  newhashrec->collision = table[ind];
  table[ind] = newhashrec;
}


/*
 * removefromhash()
 *
 *
 *      fixed memory leak here...
 *	make sure don't free() an already free()'ed info struct
 */

char removefromhash(struct hashrec *table[],
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
		  (void)free(find->info);
		}
	    }

	  (void)free(find);
	  return 1;		/* Found the item */
	}
      prev = find;
      find = find->collision;
    }
  return 0;
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

static void updateuserhost(char *nick1,char *nick2,char *userhost)
{
  char *host;

  if ( !(host = strchr(userhost,'@')) )
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

static void updatehash(struct hashrec *table[],
		       char *key,char *nick1,char *nick2)
{
  struct hashrec *find;

  for( find = table[hash_func(key)]; find; find = find->collision )
    {
      if ( !strcmp(find->info->nick,nick1) )
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

static void removeuserhost(char *nick, struct plus_c_info *userinfo)
{
  int  found_dots;
  char ip_class_c[MAX_IP];
  char *p;
  char *domain;
#ifdef DEBUGMODE
  placed;
#endif

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
#ifdef DEBUGMODE
  placed;
#endif
}


/*
 * adduserhost()
 * 
 * inputs	- nick
 * 		- user@host
 * 		- from a trace YES or NO
 * 		- is this user an oper YES or NO
 * output	- NONE
 * side effects	-
 * 
 * These days, its better to show host IP's as class C
 */

static void adduserhost(char *nick,
			struct plus_c_info *userinfo,int fromtrace,int is_oper)
{
  struct userentry *newuser;
  struct common_function *temp;
  char *par[5];
  char *domain;
  int  found_dots;
  char *p;

  par[0] = nick;
  par[1] = userinfo->user;
  par[2] = userinfo->host;
  par[3] = userinfo->ip;
  par[4] = userinfo->class;
  for (temp=user_signon;temp;temp=temp->next)
    temp->function(doingtrace, 5, par);

  newuser = (struct userentry *)malloc(sizeof(struct userentry));
  if ( !newuser )
    {
      fprintf(outfile, "Ran out of memory in adduserhost\n");
      prnt(connections[0].socket,"QUIT :Ran out of memory in adduserhost\n");
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in adduserhost\n");
      gracefuldie(0, __FILE__, __LINE__);
    }

  strncpy(newuser->nick,nick,MAX_NICK);
  newuser->nick[MAX_NICK-1] = '\0';
  strncpy(newuser->user,userinfo->user,11);
  newuser->user[MAX_NICK] = '\0';
  strncpy(newuser->host,userinfo->host,MAX_HOST);
  newuser->host[MAX_HOST-1] = '\0';
  if (userinfo->ip[0])
    strncpy(newuser->ip_host,userinfo->ip,MAX_IP);
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
      check_virtual_host_clones(newuser->ip_class_c);
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
static char* find_domain(char* host)
{
  char *ip_domain;
  char *found_domain;
  int  found_dots=0;
  int  two_letter_tld=NO;
  int is_legal_ip = YES;
  static char iphold[MAX_IP+1];
  int i = 0;
 
  ip_domain = host;

  if (isdigit(*ip_domain))
    {
      while (*ip_domain)
	{
	  iphold[i++] = *ip_domain;
	  if ( *ip_domain == '.' )
	    found_dots++;
	  else if (!isdigit(*ip_domain))
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

  if ( (found_dots != 3) || !is_legal_ip)
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
 * check_host_clones()
 * 
 * inputs	- host
 * output	- none
 * side effects	- 
 */

void check_host_clones(char *host)
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

  oldest = now = time(NULL);
  lastreport = 0;
  ind = hash_func(host);

  for( find = hosttable[ind]; find; find = find->collision )
    {
      if (!strcmp(find->info->host,host) &&
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
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_CLONES,
	     "%d more possible clones (%d total) from %s:\n",
	     clonecount, clonecount+reportedclones, host);

      log("%d more possible clones (%d total) from %s:\n",
	  clonecount, clonecount+reportedclones, host);
    }
  else
    {
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_CLONES,
	     "Possible clones from %s detected: %d connects in %d seconds\n",
	     host, clonecount, now - oldest);

      log("Possible clones from %s detected: %d connects in %d seconds\n",
	  host, clonecount, now - oldest);
    }

  for( find = hosttable[ind],clonecount = 0; find; find = find->collision)
    {
      if (!strcmp(find->info->host,host) &&
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
	      if ( *current_user == '~' )
		{
		  current_user++;
		  current_identd = NO;
		}

	      if (strcmp(last_user,current_user) != 0 && current_identd)
		different = YES;

	      suggest_action(get_action_type("clone"), find->info->nick, find->info->user,
			     find->info->host, different, current_identd);
	    }

	  find->info->reporttime = now;
	  if (clonecount == 1)
	    ;
	  else if (clonecount == 2)
	    {
	      report(SEND_ALL_USERS, CHANNEL_REPORT_CLONES, notice1);
	      log("%s", notice1);

	      report(SEND_ALL_USERS, CHANNEL_REPORT_CLONES, notice0);
	      log("%s", notice0);
	    }
	  else if (clonecount < 5)
	    {
	      report(SEND_ALL_USERS, CHANNEL_REPORT_CLONES, notice0);
	      log("%s", notice0);
	    }
	  else if (clonecount == 5)
	    {
	      sendtoalldcc(SEND_ALL_USERS, notice0);
	      log("  [etc.]\n");
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
 */

void check_virtual_host_clones(char *ip_class_c)
{
  struct hashrec *find;
  int clonecount = 0;
  int reportedclones = 0;
  time_t now, lastreport, oldest;
  char notice1[MAX_BUFF];
  char notice0[MAX_BUFF];
  struct tm *tmrec;
  int ind;

  oldest = now = time(NULL);
  lastreport = 0;

  ind = hash_func(ip_class_c);

  for( find = iptable[ind]; find; find = find->collision )
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

  if ((reportedclones == 0 && clonecount < CLONECONNECTCOUNT) ||
      now - lastreport < 10)
    return;

  if (reportedclones)
    {
      report(SEND_WARN_ONLY,
	     CHANNEL_REPORT_VCLONES,
	     "%d more possible virtual host clones (%d total) from %s.*:\n",
	     clonecount, clonecount+reportedclones, ip_class_c);

      log("%d more possible virtual host clones (%d total) from %s.*:\n",
	  clonecount, clonecount+reportedclones, ip_class_c);
    }
  else
    {
      report(SEND_WARN_ONLY,
	     CHANNEL_REPORT_VCLONES,
	     "Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	     ip_class_c, clonecount, now - oldest);

      log("Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	    ip_class_c, clonecount, now - oldest);
    }

  clonecount = 0;

  for ( find = iptable[ind]; find; find = find->collision )
    {
      if (!strcmp(find->info->ip_class_c,ip_class_c) &&
	  (now - find->info->connecttime < CLONECONNECTFREQ + 1) &&
	  find->info->reporttime == 0)
	{
	  ++clonecount;
	  tmrec = localtime(&find->info->connecttime);

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

	      suggest_action(get_action_type("vclone"), find->info->nick, find->info->user,
			     find->info->host, NO, NO);
	    }

	  find->info->reporttime = now;
	  if (clonecount == 1)
	    ;
	  else if (clonecount == 2)
	    {
	      report(SEND_WARN_ONLY, CHANNEL_REPORT_VCLONES, notice1);
	      log("%s", notice1);

	      report(SEND_WARN_ONLY, CHANNEL_REPORT_VCLONES, notice0);
	      log("%s", notice0);
	    }
	  else if (clonecount < 5)
	    {
	      report(SEND_WARN_ONLY, CHANNEL_REPORT_VCLONES, notice0);
	      log("%s", notice0);
	    }
	  else if (clonecount == 5)
	    {
	      sendtoalldcc(SEND_WARN_ONLY, notice0);
	      log("  [etc.]\n");
	    }
	}

    }
}

static void connect_flood_notice(char *server_notice)
{
  char *nick_reported;
  char *user_host;
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  char *ip;
  char *p;
  time_t current_time;
  int first_empty_entry = -1;
  int found_entry = NO;
  int i;

  current_time = time(NULL);
  server_notice +=5;

  p=nick_reported=server_notice;
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

	      if (!okhost(user, host))
		{
		  if (connect_flood[i].connect_count >= MAX_CONNECT_FAILS)
		    {
		      if (!strncasecmp((char *)get_action_method("cflood"), "dline", 5))
			suggest_action(get_action_type("cflood"), nick_reported, user, ip,
                                       NO, YES);
		      else
			suggest_action(get_action_type("cflood"), nick_reported, user, host,
                                       NO, YES);
		      connect_flood[i].user_host[0] = '\0';
		    }
		}
	      else
		{
		  connect_flood[i].last_connect = current_time;
		}
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
 *
 * ARGGHHHHH
 *
 * +th ircd has "LINKS '...' requested by "
 * where ... is usualy blank or a server name etc.
 * LT and CS do not. sorry guys for missing that. :-(
 *  Jan 1 1997  - Dianora
 */
static void link_look_notice(char *server_notice)
{
  char *nick_reported;
  char *user_host;
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  char *s;			/* used for source copy */
  char *d;			/* used for destination copy */
  char n;			/* used for max length copy */
  char *p;
  time_t current_time;
  int first_empty_entry = -1;
  int found_entry = NO;
  int i;

  current_time = time(NULL);

  p = strstr(server_notice,"requested by");

  if (!p)
    return;

  nick_reported = p + 13;

  if ((p = strchr(nick_reported,' ')))
    *p = '\0';
  else
    return;
  p++;

  user_host = p;
/*
 *  Lets try and get it right folks... [user@host] or (user@host)
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

  s = user_host;
  d = user;
  n = MAX_NICK;
  while(*s)
    {
      if (*s == '@')
	break;
      *d++ = *s++;
      n--;
      if (n == 0)
	break;
    }
  *d = '\0';
  s++;

  d = host;
  n = MAX_HOST;
  while(*s)
    {
      *d++ = *s++;
      n--;
      if (n == 0)
	break;
    }
  *d = '\0';
  
  /* Don't even complain about opers */

  sendtoalldcc(SEND_LINK_ONLY,
	       "[LINKS by %s (%s@%s)]\n",
	       nick_reported, user, host ); /* - zaph */

  if ( isoper(user,host) )  
    {
      if (config_entries.debug && outfile)
	{
	  (void)fprintf(outfile, "DEBUG: is oper\n");
	}
      return;
    }


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
		  sendtoalldcc(SEND_WARN_ONLY,
			       "possible LINK LOOKER nick [%s]\n", 
			       nick_reported,user_host);

		  log("possible LINK LOOKER  = %s [%s]\n",
		      nick_reported,user_host);

		  if ( !okhost(user,host) )
		    {
		      if (*user == '~')
			suggest_action(get_action_type("link"), nick_reported, user+1, host,
				       NO, NO);
		      else
			suggest_action(get_action_type("link"), nick_reported, user, host,
				       NO, YES);
		    }

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
	  link_look[first_empty_entry].link_look_count = 0;
	}
    }
}

/*
 * bot_report_kline()
 *
 * inputs	- server notice after the bot notice
 * output	- NONE
 * side effects	- generates a suggested kline for bot
 */

#ifdef BOT_WARN
void bot_report_kline(char *server_notice,char *type_of_bot)
{
  char *p;			/* scratch variable */
  char *nick;			/* found nick */
  char *user_host;		/* user@host */
  char *user;			/* user */
  char *host;			/* host */

  if ( !(nick = strtok(server_notice," ")) )
    return;

  if ( !(user_host = strtok(NULL," ")) )
    return;

  if (*user_host == '[')
    *user_host++;
  if ( !(p = strrchr(user_host,']')) )
    return;
  *p = '\0';		

  user = user_host;	
  if ( !(p = strchr(user_host,'@')) )
    return;
  *p = '\0';

  host = p;	
  host++;

  sendtoalldcc(SEND_WARN_ONLY,"%s bot [%s!%s@%s]",
	       type_of_bot,
	       nick,	
	       user,
	       host);

  suggest_action(get_action_type("bot"), nick, user, host, NO, YES);

  log("bot warning [%s@%s]\n", user, host);
}
#endif

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
static void cs_nick_flood(char *server_notice)
{
  char *nick_reported;
  char *user_host;
  char *user;
  char *host;
  char *p;

  if ( !(nick_reported = strtok(server_notice," ")) )
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

  sendtoalldcc(SEND_WARN_ONLY, "CS nick flood user_host = [%s]", user_host);

  log("CS nick flood user_host = [%s]\n", user_host);


  if ( !(user = strtok(user_host,"@")) )
    return;

  if ( !(host = strtok(NULL,"")) )
    return;

  if ( (!okhost(user,host)) && (!isoper(user,host)) )  
    {
      if (*user_host == '~')
	suggest_action(get_action_type("flood"), nick_reported, user, host, NO, NO);
      else
	suggest_action(get_action_type("flood"), nick_reported, user, host, NO, YES);
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
static void cs_clones(char *server_notice)
{
  int identd = YES;
  char *user;
  char *host;
  char *p;
  char *user_host;

  if ( !(strtok(server_notice," ") == NULL) )
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

  sendtoalldcc(SEND_WARN_ONLY, "CS clones user_host = [%s]\n", user_host);
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

  suggest_action(get_action_type("clone"), "", user, host, NO, identd);
}

/*
 * check_nick_flood()
 *
 * inputs	- rest of notice from server
 * output	- NONE
 * side effects
 *
 */

static void check_nick_flood(char *server_notice)
{
  char *p;
  char *nick1;
  char *nick2;
  char *user_host;

  if ( !(p = strtok(server_notice," ")) )	/* Throw away the "From" */
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

      if (strcmp(p,"as"))
	return;

      if ( !(nick2 = strtok(NULL," ")) )
	return;

      add_to_nick_change_table(user_host,nick2);
      updateuserhost(nick1,nick2,user_host);

      return;
    }

  if ( !(nick1 = strtok(NULL," ")) )
    return;

  if ( !(p = strtok(NULL," ")) )	/* Throw away the "to" */
    return;

  if ( !(nick2 = strtok(NULL," ")) )	/* This _should_ be nick2 */
    return;

  if ( !(user_host = strtok(NULL," ")) )	/* u@h  */
    return;

  if (*user_host == '[')
    user_host++;

  if ( (p = strrchr(user_host,']')) )
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
 * side effects -
 * clears out the link looker change table
 * This is very similar to the NICK_CHANGE code in many respects
 *
 */

void init_link_look_table()
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

static void add_to_nick_change_table(char *user_host,char *last_nick)
{
  char *user;
  char *host;
  int i;
  int found_empty_entry=-1;
  time_t current_time;
  struct tm *tmrec;

  current_time = time(NULL);

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
    {
      if ( nick_changes[i].user_host[0] )
	{
	  time_t time_difference;
	  int time_ticks;

	  time_difference = current_time - nick_changes[i].last_nick_change;

	  /* is it stale ? */
	  if ( time_difference >= NICK_CHANGE_T2_TIME )
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

		  if ( !(strcasecmp(nick_changes[i].user_host,user_host)) )
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

		      sendtoalldcc(SEND_WARN_ONLY,
	    "nick flood %s (%s) %d in %d seconds (%2.2d:%2.2d:%2.2d)\n",
				    nick_changes[i].user_host,
				    nick_changes[i].last_nick,
				    nick_changes[i].nick_change_count,
				    nick_changes[i].last_nick_change-
				    nick_changes[i].first_nick_change,
				    tmrec->tm_hour,
				    tmrec->tm_min,
				    tmrec->tm_sec);


		      if ( !(user = strtok(user_host,"@")) )
			return;
		      if ( !(host = strtok(NULL,"")) )
			return;
		      
		      if (*user_host == '~')
			suggest_action(get_action_type("flood"), last_nick, user, host, NO, NO);
		      else
			suggest_action(get_action_type("flood"), last_nick, user, host, NO, YES);
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
	  if ( found_empty_entry < 0 )
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
 * bot_reject()
 *
 * inputs	- reject message from server
 * output		- NONE
 * side effects	- logs the failure
 *
 */

static void bot_reject(char *text)
{
  char generic = 0;
  char *p;

  if (text)
    {
      if (strncmp("bot:",text,4) == 0)
	generic = YES;

      if ( !(text = strchr(text,' ')) )
	return;

      p = strstr(text+1,"(Single");
      if (p)
	{
	  while(p != text)
	    {
	      if (*p == ']')
		{
		  p++;
		  *p = '\0';
		  break;
		}
	      p--;
	    }
	}
      if (!generic)
	{
	  if ( !(text = strchr(text+1,' ')) )
	    return;
	}

      logfailure(text+1,1);
    }
}

/*
 * stats_notice
 * 
 * inputs		- notice
 * output		- none
 * side effects 	-
 */

static void stats_notice(char *server_notice)
{
  char *nick;
  char *fulluh;
  char *p;
  int i;
  int number_of_tcm_opers=0;
  int stat;
#ifdef DEBUGMODE
  placed;
#endif

  stat = *server_notice;

  if ( !(nick = strstr(server_notice,"by")) )
    return;

  nick += 3;

  if ( (p = strchr(nick, ' ')) )
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
#ifdef DEBUGMODE
      placed;
#endif

      for (i=1;i<maxconns;++i)
	{
#ifdef DEBUGMODE
          placed;
#endif

	  /* ignore bad sockets */
	  if (connections[i].socket == INVALID)
	    continue;

	  /* ignore tcm connections */
	  if (connections[i].type & TYPE_TCM)
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

  sendtoalldcc(SEND_OPERS_STATS_ONLY, "[STATS %c requested by %s (%s)]\n",
	       stat, nick, fulluh);
}

void _reload_bothunt(int connnum, int argc, char *argv[])
{
#ifdef DEBUGMODE
  placed;
#endif
 if (!amianoper) oper();
}

void _prefsave_bothunt(int connnum, int argc, char *argv[])
{
  char buffer[1024];
  if (buffer[0]) memset((char *)&buffer,0,sizeof(buffer));

  snprintf(buffer, sizeof(buffer), "A:cflood:%s:%s:%d\n", get_action_method("cflood"),
           get_action_reason("cflood"), action_log("cflood"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:spambot:%s:%s:%d\n", get_action_method("spambot"),
           get_action_reason("spambot"), action_log("spambot"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:clone:%s:%s:%d\n", get_action_method("clone"),
           get_action_reason("clone"), action_log("clone"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:ctcp:%s:%s:%d\n", get_action_method("ctcp"),
           get_action_reason("ctcp"), action_log("ctcp"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:flood:%s:%s:%d\n", get_action_method("flood"),
           get_action_reason("flood"), action_log("flood"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:link:%s:%s:%d\n", get_action_method("link"),
           get_action_reason("link"), action_log("link"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:bot:%s:%s:%d\n", get_action_method("bot"),
           get_action_reason("bot"), action_log("bot"));
  write(connnum, buffer, strlen(buffer));

  snprintf(buffer, sizeof(buffer), "A:vclone:%s:%s:%d\n", get_action_method("vclone"),
           get_action_reason("vclone"), action_log("vclone"));
  write(connnum, buffer, strlen(buffer));
}

void _config_bothunt(int connnum, int argc, char *argv[])
{
  if (*argv[0] != 'A' && *argv[0] != 'a') return;

  if (!strcasecmp(argv[1], "cflood") || !strcasecmp(argv[1], "spambot") || 
      !strcasecmp(argv[1], "clone")  || !strcasecmp(argv[1], "ctcp") || 
      !strcasecmp(argv[1], "flood")  || !strcasecmp(argv[1], "link") || 
      !strcasecmp(argv[1], "bot")    || !strcasecmp(argv[1], "vclone"))
    {
      if (argc >= 3) set_action_method(argv[1], argv[2]);
      if (argc >= 4) set_action_reason(argv[1], argv[3]);
    }
}

void _modinit()
{
  add_common_function(F_CONFIG, _config_bothunt);
  add_common_function(F_PREFSAVE, _prefsave_bothunt);
  add_common_function(F_RELOAD, _reload_bothunt);
  add_common_function(F_SERVER_NOTICE, onservnotice);
  add_common_function(F_ONCTCP, _onctcp);
  add_common_function(F_ONTRACEUSER, _ontraceuser);
  add_common_function(F_ONTRACECLASS, _ontraceclass);
  add_common_function(F_STATSI, on_stats_i);
  add_common_function(F_STATSK, on_stats_k);
  add_common_function(F_STATSE, on_stats_e);
  add_common_function(F_STATSO, on_stats_o);
  memset(&usertable,0,sizeof(usertable));
  memset(&hosttable,0,sizeof(usertable));
  memset(&domaintable,0,sizeof(usertable));
#ifdef VIRTUAL
  memset(&iptable,0,sizeof(iptable));
#endif
  memset(&nick_changes,0,sizeof(nick_changes));
  init_link_look_table();
  add_action("cflood", "dline", "Connect flooding", YES);
  set_action_type("cflood", R_CFLOOD);
  add_action("vclone", "warn", "Cloning is prohibited", YES);
  set_action_type("vclone", R_VCLONE);
  add_action("flood", "kline", "Flooding is prohibited", YES);
  set_action_type("flood", R_FLOOD);
  add_action("link", "kline 180", "Link lookers are prohibited", YES);
  set_action_type("link", R_LINK);
  add_action("bot", "kline", "Bots are prohibited", YES);
  set_action_type("bot", R_BOT);
  add_action("ctcp", "kline", "CTCP flooding", YES);
  set_action_type("ctcp", R_CTCP);
  add_action("spambot", "warn", "Spamming is prohibited", YES);
  set_action_type("spambot", R_SPAMBOT);
  add_action("clone", "kline", "Cloning is prohibited", YES);
  set_action_type("clone", R_CLONE);
}
