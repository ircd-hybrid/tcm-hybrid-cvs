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
#include "abuse.h"
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

static char *version="$Id: bothunt.c,v 1.1 2001/09/19 03:30:21 bill Exp $";

static char* find_domain( char* domain );
static void  free_hash_links( struct hashrec *ptr );
static void  check_nick_flood( char *server_notice );
static void  cs_nick_flood( char *server_notice );
static void  cs_clones( char *server_notice );
static void  link_look_notice( char *server_notice );
static void  connect_flood_notice( char *server_notice );
static void  add_to_nick_change_table( char *user_host, char *last_nick );
static void  bot_reject( char *text );
static void  adduserhost( char *, struct plus_c_info *, int, int);
static int   obvious_dns_spoof( char *nick, struct plus_c_info *userinfo);
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

#ifdef DETECT_DNS_SPOOFERS
static int   host_is_ip(char *host_name);
#endif

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


struct hashrec *usertable[HASHTABLESIZE];
struct hashrec *hosttable[HASHTABLESIZE];
struct hashrec *domaintable[HASHTABLESIZE];
struct hashrec *iptable[HASHTABLESIZE];

extern struct connection connections[];

struct sortarray 
{
  struct userentry *domainrec;
  int count;
};

char doingtrace = NO;

struct failrec *failures = (struct failrec *)NULL;

/* nick flood finding code */

#define NICK_CHANGE_TABLE_SIZE 100

struct nick_change_entry
{
  char user_host[MAX_USER+MAX_HOST];
  char last_nick[MAX_NICK];
  int  nick_change_count;
  time_t first_nick_change;
  time_t last_nick_change;
  int noticed;
};

struct nick_change_entry nick_changes[NICK_CHANGE_TABLE_SIZE];

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
 * ontraceuser()
 * 
 * inputs	- traceline from server
 * output	- NONE
 * side effects	- user is added to hash tables
 * 
 * 
 * texas went and modified the output of /trace in their irc server
 * so that it appears as "nick [user@host]" ontraceuser promptly
 * threw out the "[user@host]" part.. *sigh* I've changed the code
 * here to check for a '[' right after a space, and not blow away
 * the "[user@host]" part. - Dianora
 * 
 * This is moot now, as no one now runs this variant...
 */

void ontraceuser(char *traceline)
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

  if(*traceline == 'O')
    {
      is_oper = YES;
    }
  else
    {
      is_oper = NO;
    }

  /* /trace format the same now everywhere? */

  right_bracket_ptr = traceline + strlen(traceline);

  while(right_bracket_ptr != traceline)
    {
      if( *right_bracket_ptr == ')' )
	{
	  *right_bracket_ptr = '\0';
	  break;
	}
      right_bracket_ptr--;
    }

  ip_ptr = right_bracket_ptr;
  while(ip_ptr != traceline)
    {
      if( *ip_ptr == '(' )
	{
	  ip_ptr++;
	  break;
	}
      ip_ptr--;
    }

  if( (nuh = strchr(traceline,' ')) )    /* Skip 'User' */
    {
      class_ptr = nuh;			/* point to the class number */
      if( (nuh = strchr(nuh+1,' ')) )      /* Skip class */
	{
	  *nuh = '\0';
	  ++nuh;
	  if ( (userhost = strchr(nuh,' ')) )
	    {
	      if(userhost[1] != '[')
		userhost[0] = '\0';
	      else	/* clean up garbage */
		{
		  if( (p = strchr(userhost+1,' ')) )
		    *p = '\0';
		}
	    }
	  chopuh(YES,nuh,&userinfo);
	  if (*class_ptr == ' ') ++class_ptr;
	  snprintf(userinfo.class, sizeof(userinfo.class) - 1, "%s", class_ptr);

	  /* old -5 hybrid does not have IP in /trace ;-( 
	   * quick hack is to look for '.' in ip
	   */
	  if(strchr(ip_ptr,'.'))
	    userinfo.ip = ip_ptr;
	  else
	    userinfo.ip = NULL;

	  adduserhost(nuh,&userinfo,YES,is_oper);
	}
    }
}

void ontraceclass()
{
  if (doingtrace)
    {
      doingtrace = NO;
      if(config_entries.defchannel_key[0])
	join(config_entries.defchannel,config_entries.defchannel_key); 
      else
	join(config_entries.defchannel,(char *)NULL);
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

void on_stats_o(char *body)
{
  char *user_at_host;
  char *user;
  char *host;
  char *nick;
  int non_lame_user_o;	/* If its not a wildcarded user O line... */
  int non_lame_host_o;	/* If its not a wildcarded host O line... */
  char *p;		/* pointer used to scan for valid O line */

/* No point if I am maxed out going any further */
  if( user_list_index == (MAXUSERS - 1))
    return;

  if( !(p = strchr(body,' ')) )
    return;
  p++;

  user_at_host = p;		/* NOW its u@h */
  if( !(p = strchr(user_at_host,' ')) )
    return;
  *p = '\0';
  p++;

  if( !(p = strchr(p, ' ')) )
    return;
  p++;
  nick = p;

  if( !(p = strchr(nick, ' ')) )
    return;
  *p = '\0';
  
  p = user_at_host;
  non_lame_user_o = NO;

  while(*p)
    {
      if(*p == '@')	/* Found the first part of "...@" ? */
	break;

      if(*p != '*')	/* A non wild card found in the username? */
	non_lame_user_o = YES;	/* GOOD a non lame user O line */
      /* can't just break. I am using this loop to find the '@' too */

      p++;
    }
  
  if(!non_lame_user_o)	/* LAME O line ignore it */
    return;

  p++;			/* Skip the '@' */
  non_lame_host_o = NO;

  while(*p)
    {
      if(*p != '*')	/* A non wild card found in the hostname? */
	non_lame_host_o = YES;	/* GOOD a non lame host O line */
      p++;
    }

  if(non_lame_host_o)
    {
      user = user_at_host;

      if( (p = strchr(user_at_host,'@')) )
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

      if( !isoper(user,host) )
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
}

/* 
 * on_stats_e()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- exception list of tcm is built up from stats E of server
 * 
 */

void on_stats_e(char *body)
{
  char *user;
  char *host;

/* No point if I am maxed out going any further */
  if( host_list_index == (MAXHOSTS - 1))
    return;

  if( !(strtok(body," ") == NULL) )		/* discard this field */
    return;

  /* should be 'E' */
    
  if( !(host = strtok((char *)NULL," ")) )
    return;

  if( !(strtok((char *)NULL," ") == NULL) )
    return;

  if( !(user = strtok((char *)NULL," ")) )	/* NOW user */
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

void on_stats_i(char *body)
{
  char *user;
  char *host;
  char *p;
  int  alpha=NO;

/* No point if I am maxed out going any further */
  if( host_list_index == (MAXHOSTS - 1))
    return;

  if( !( p = strchr(body,'@')) )	/* find the u@h part */
    return;

  *p = '\0';				/* blast the '@' */
  host = p;
  host++;				/* host part is past the '@' */

  while(p != body)			/* scan down for first ' ' */
    {
      if(*p == ' ')
	break;
      p--;
    }

  if( p == body )			/* bah not found */
    return;

  p++;

  /* if client is exempt, mark it as such in the exemption list */

  if( !(p = strchr(p,'>')) )
    return;

  for(;*p;p++)
    {
      switch(*p)
	{
	case '=':case '!':case '-':case '$':
	case '%':case '^':case '&':case '>':
	case '<':
	  break;

	default:
	  alpha = YES;
	  break;
	}
      if(alpha)
	break;
    }

  user = p;

  if( !(p = strchr(host,' ')) )		/* blast ' ' following the host */
    return;
  *p = '\0';


  strncpy(hostlist[host_list_index].user, user,
	  sizeof(hostlist[host_list_index].user));

  strncpy(hostlist[host_list_index].host, host,
	  sizeof(hostlist[host_list_index].host));

  host_list_index++;
}

/* 
 * on_stats_k()
 *
 * inputs	- body of server message
 * output	- none
 * side effects	- 
 * 
 */

void on_stats_k(char *body)
{
  char *user;
  char *host;
  char *p;

  if( !(p = strchr(body,' ')) )
    return;
  p++;

  host = p;
  if( !(p = strchr(host,' ')) )
    return;
  *p = '\0';
  p++;

  if( !(p = strchr(p, ' ')) )
    return;
  p++;

  user = p;
  if( !(p = strchr(user, ' ')) )
    return;
  *p = '\0';
  ++p;

}

/*
 * kfind
 *
 * inputs	- socket to report error on
 * 		- pattern to search for
 * output	- NONE
 * side effects -
 */

void kfind(int sock, char *pattern)
{
  char *p;
  
  if(config_entries.hybrid)
    {
      if(config_entries.hybrid_version >= 6)
	{
	  prnt(sock,"[TESTLINE %s]\n", pattern);
	  toserv("TESTLINE %s\n", pattern );
	}
      else
	{
	  prnt(sock,"[STATS K %s %s]\n",
	       config_entries.rserver_name, pattern);
	  toserv("STATS K %s %s\n", config_entries.rserver_name, pattern );
	}
    }
  else
    {
      prnt(sock,"[STATS K]\n");
      toserv("STATS K\n");
    }

  if( (p = strchr(pattern,'@')) )
    {
      *p = '\0';
      strncpy(to_find_k_user,pattern,MAX_USER-1);
      p++;
      strncpy(to_find_k_host,p,MAX_HOST-1);
    }
  else
    {
      strcpy(to_find_k_user,"*");
      strncpy(to_find_k_host,pattern,MAX_HOST-1);
    }

  prnt(sock,"to_find_k_user [%s]\n", to_find_k_user );
  prnt(sock,"to_find_k_host [%s]\n", to_find_k_host );
}

#ifdef DETECT_DNS_SPOOFERS

/*
 * confirm_match_ip
 * 
 * inputs	- nick of user
 * 		- ip of seen host
 *              - actual hostname seen
 * output	- NONE
 * side effects	- reverse lookup of hostname as given is done,
 * 		  the ip is then compared with the dns resolved
 *           	  hostname the server "saw"
 * 		  if a mismatch is found, connected opers are messaged
 * 		  about it.
 * BUGS:
 * 	It would be better to do a top level domain match only, i.e.
 *	don't panic about CNAMES or recently changed hostnames etc.
 * 	I'll get to that... Thats why I am not checking all CNAMES
 *	as returned from gethostbyaddr() - Dianora
 *
 */

void confirm_match_ip(char *nick,char *iphost,char *host)
{
  unsigned long ip_long;	/* equivalent ip address as long */
  struct hostent *host_seen;
  struct hashrec *userptr;
  char notice[MAX_BUFF];

  if(host_is_ip(host)) /* If its an IP# don't even continue */
    return;

  ip_long = inet_addr(iphost);
  host_seen = gethostbyaddr((char *)&ip_long,sizeof(unsigned long),AF_INET);

  if(host_seen)
    {
      if(strcasecmp(host_seen->h_name,host) != 0)
        {
	  report(SEND_WARN_ONLY,
		 CHANNEL_REPORT_SPOOF,
		 " possible dns spoofed nick %s@%s claimed %s found %s\n",
		 nick,iphost,
		 host,host_seen->h_name);

	  log("possible dns spoofed nick %s@%s claimed %s locally found %s\n",
	      nick,iphost,
	      host,host_seen->h_name);
	}
    }
}

#endif
/* endif for DETECT_DNS_SPOOFERS */

#ifdef DETECT_DNS_SPOOFERS
/*
 * host_is_ip
 * 
 * inputs	- hostname
 * output	- YES if hostname is ip# only NO if its not
 * side effects	- NONE
 *
 */

static int host_is_ip(char *host_name)
{
  int number_of_dots = 0;

  while(*host_name)
    {
      if( *host_name == '.' )
	{
	  host_name++;
	  number_of_dots++;
	}
      else if( !isdigit(*host_name) )
	return(NO);
      host_name++;
    }

  if(number_of_dots == 3 )
    return(YES);
  else
    return(NO);
}
#endif

/*
 *   Chop a string of form "nick [user@host]" or "nick[user@host]" into
 *   nick and userhost parts.  Return pointer to userhost part.  Nick
 *   is still pointed to by the original param.  Note that since [ is a
 *   valid char for both nicks and usernames, this is non-trivial.
 */
/* Also, for digi servers, added form of "nick (user@host)" */

/*
 * Due to the fact texas net irc servers changed the output of the /trace
 * command slightly, chopuh() was coring... I've made the code a bit
 * more robust - Dianora
 * 
 */

void chopuh(int istrace,char *nickuserhost,struct plus_c_info *userinfo)
{
  char *uh;
  char *p;
  char skip = NO;
  char *right_brace_pointer;
  char *right_square_bracket_pointer;
#ifdef DEBUGMODE
  placed;
#endif

/* I try to pick up an [IP] from a connect or disconnect message
 * since this routine is also used on trace, some heuristics are
 * used to determine whether the [IP] is present or not.
 * *sigh* I suppose the traceflag could be used to not even go 
 * through these tests
 * bah. I added a flag -Dianora
 */

  userinfo->user = (char *)NULL;
  userinfo->host = (char *)NULL;
  userinfo->ip = (char *)NULL;

  /* ok, if its a hybrid server or modified server,
   * I go from right to left picking up extra bits
   * [ip] {class}, then go and pick up the nick!user@host bit
   */

  if(!istrace)	/* trace output is not the same as +c output */
    {
      snprintf(userinfo->class, sizeof(userinfo->class) - 1, "unknown");

      p = nickuserhost;
      while(*p)
	p++;

      right_square_bracket_pointer = (char *)NULL;
      right_brace_pointer = (char *)NULL;

      while( p != nickuserhost )
	{
	  if(right_square_bracket_pointer == (char *)NULL)
	    if(*p == ']')	/* found possible [] IP field */
	      right_square_bracket_pointer = p;

	  if(*p == '}') /* found possible {} class field */
	    right_brace_pointer = p;

	  if(*p == ')')	/* end of scan for {} class field and [] IP field */
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
		  p = (char *)NULL;
		  break;
		}
	      else
		p--;
          }

        if(p)
          {
            userinfo->ip = p;
          }
      }
    }

  /* If it's the first format, we have no problems */
  if ( !(uh = strchr(nickuserhost,' ')) )
    {
      if( !(uh = strchr(nickuserhost,'[')) )
	{
	  if( !(uh = strchr(nickuserhost,'(')) )	/* lets see... */
	    {					/* MESSED up GIVE UP */
	      (void)fprintf(stderr,
			    "You have VERY badly screwed up +c output!\n");
	      (void)fprintf(stderr,
			    "1st case nickuserhost = [%s]\n", nickuserhost);
	      return;		/*screwy...prolly core in the caller*/
	    }

	  if( (p = strrchr(uh,')')) )
	    {
	      *p = '\0';
	    }
	  else
	    {
	      (void)fprintf(stderr,
			    "You have VERY badly screwed up +c output!\n");
	      (void)fprintf(stderr,
			    "No ending ')' nickuserhost = [%s]\n",
			    nickuserhost);
	      /* No ending ')' found, but lets try it anyway */
	    }
          userinfo->user = uh;

	  if( (p = strchr(userinfo->user,'@')) )
	    {
              *p = '\0';
              p++;
              userinfo->host = p;
	    }
	  return;
	}

      if (strchr(uh+1,'['))
	{
	  /*moron has a [ in the nickname or username.  Let's do some AI crap*/
	  uh = strchr(uh,'~');
	  if (!uh)
	    {
	      /* No tilde to guess off of... means the lamer checks out with
		 identd and has (more likely than not) a valid username.
		 Find the last [ in the string and assume this is the
		 divider, unless it creates an illegal length username
		 or nickname */
	      uh = nickuserhost + strlen(nickuserhost);
	      while (--uh != nickuserhost)
		if (*uh == '[' && *(uh+1) != '@' && uh - nickuserhost < 10)
		  break;
	    }
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

  *(uh++) = 0;
  if (skip)
    ++uh;                 /* Skip [ */
  if (strchr(uh,' '))
    *(strchr(uh,' ')) = 0;
  if (uh[strlen(uh)-1] == '.')
    uh[strlen(uh)-2] = 0;   /* Chop ] */
  else
    uh[strlen(uh)-1] = 0;   /* Chop ] */
  userinfo->user = uh;

  if( (p = strchr(userinfo->user,'@')) )
    {
      *p = '\0';
      p++;
      userinfo->host = p;
    }
#ifdef DEBUGMODE
  placed;
#endif
  return;
}

/*
 * onservnotice()
 *
 * inputs	- message from server
 * output	- NONE
 * side effects	-
 */

static void onservnotice(int connnum, int argc, char *argv[])
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

  for (i=0;i<argc;++i)
    {
      strcat((char *)&message, argv[i]);
      strcat((char *)&message, " ");
    }
  if (message[strlen(message)-1] == ' ') message[strlen(message)-1] = '\0';

  i = -1;
  while (msgs_to_mon[++i])
    {
      if (!strncmp(message,msgs_to_mon[i],strlen(msgs_to_mon[i])))
	{
	  message += strlen(msgs_to_mon[i]);
	  break;
	}
    }

  /*
   * I added a few things here, including several additions to msgs_to_mon
   * -bill
   */

  if (strstr(message, "closed the connection") &&
      !strncmp(message, "Server", 6)) 
    {
      q = split(message);
      q = split(q);
      sendtoalldcc(SEND_LINK_ONLY, "Lost server: %s\n", q);
      return;
    }

  /* Kline notice requested by Toast */
  if (strstr(message, "added K-Line for"))
    {
      kline_add_report(message);
      return;
    }

  if (strstr(message, "KILL message for"))
    {
      kill_add_report(message);
      return;
    }

  switch (i)
    {
    case CONNECT:
      chopuh(NO,message,&userinfo);
      adduserhost(message,&userinfo,NO,NO);
      break;

    case EXITING:
      chopuh(NO,message,&userinfo);
      removeuserhost(message,&userinfo);
      break;

    case UNAUTHORIZED:
      p = strstr(message,"from");
      if(p)
        {
	  p += 4;
	  message = p;
	}
      logfailure(message,0);
      break;
    case REJECTING:
      bot_reject(message);
      break;
    case TOOMANY:
      logfailure(message,0);
      break;
    case NICKCHANGE:
      check_nick_flood(message);
      break;
/* CS style of reporting nick flooding */
    case CS_NICKFLOODING:
      cs_nick_flood(message);
      break;
    case CS_CLONES:
    case CS_CLONEBOT_KILLED:
      cs_clones(message);
      break;
    case LINK_LOOK:
      link_look_notice(message);
      break;
    case STATS:
      stats_notice(message);
      break;
    case JOHBOT:
#ifdef DEBUGMODE
      placed;
#endif
#ifdef BOT_WARN
      bot_report_kline(message,"johbot");
#endif
      break;
    case EGGDROP:
#ifdef DEBUGMODE
      placed;
#endif
#ifdef BOT_WARN
      bot_report_kline(message,"eggdrop");
#endif
      break;
    case LINKWITH:
      ++message;
      
      sendtoalldcc(SEND_LINK_ONLY, "Link with %s\n", message);
      break;

    case WRITEERR:
      ++message;
      q = split(message);

      if( (p = strchr(q,',')) )
	*p = '\0';

      sendtoalldcc(SEND_LINK_ONLY, "Write error to %s, closing link.\n", q);
      break;

    case SQUITOF:
      ++message;
      q = split(message);
      q = split(q);
      r = split(q);
      sendtoalldcc(SEND_LINK_ONLY, "SQUIT for %s from %s\n", q, r);
      break;

    case MOTDREQ:
      ++message;
      sendtoalldcc(SEND_MOTD_ONLY, "[MOTD requested by %s]\n", message);
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
      ++message;
      if(!(p = strchr(message,' ')))
	break;

      *p = '\0';
      p++;
      nick = message;

      user = p;
      if(!(p = strchr(user,'[')))
	break;
      p++;
      user = p;

      if(!(p = strchr(user,'@')))
	break;
      *p = '\0';
      p++;

      host = p;
      if(!(p = strchr(host,']')))
	break;
      *p = '\0';
      p++;

      if(*p != ' ')
	break;
      p++;

      /* p =should= be pointing at "on" */
      if(!(p = strchr(p,' ')))
	break;
      p++;

      from_server = p;
      if(!(p = strchr(from_server,' ')))
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

      if(!strcasecmp(config_entries.rserver_name,from_server))
	{
	  if(*user == '~')
	    user++;

	  suggest_action(get_action_type("ctcp"),
			     nick,
			     user,
			     host,
			     NO,
			     YES);
	}

      break;

    case SPAMBOT:
      ++message;
      if(!(p = strchr(message,' ')))
	break;

      *p = '\0';
      p++;
      nick = message;

      user = p;
      if(!(p = strchr(user,'(')))
	break;
      p++;
      user = p;

      if(!(p = strchr(user,'@')))
	break;
      *p = '\0';
      p++;

      host = p;
      if(!(p = strchr(host,')')))
	break;
      *p = '\0';
      p++;

      if(!strstr(p,"possible spambot"))
	break;

      suggest_action(get_action_type("spambot"),
			 nick,
			 user,
			 host,
			 NO,
			 YES);
      break;

    case ILINEFULL:
      connect_flood_notice(message);
      break;

    default:
      sendtoalldcc(SEND_OPERS_NOTICES_ONLY, message);
      break;
    }
}

void ilinemask(char *body)
{
  sendtoalldcc(SEND_OPERS_NOTICES_ONLY, body );
}

/*
 * onctcp
 * inputs	- nick
 *		- user@host
 * 		- text argument
 * output	- NONE
 *
 */

void onctcp(char *nick, char *userhost, char *text)
{
  char *hold;
  char dccbuff[DCCBUFF_SIZE];

  dccbuff[0] = '#';
  ++text;
  if (!strncasecmp(text,"PING",4))
    {
      notice(nick,text-1);
    }
  else if (!strncasecmp(text,"VERSION",7))
    {
      notice(nick,"\001VERSION %s(%s)\001",VERSION,SERIALNUM);
    }
  else if (!strncasecmp(text,"DCC CHAT",8))
    {
      text += 9;
      if( (hold = strchr(text,' ')) )  /* Skip word 'Chat' */
	{
	  text = hold+1;
	  if( (hold = strchr(text,' ')) )
	    {
	      *(hold++) = ':';
	      strncpy(dccbuff+1,text,119);
	      if (atoi(hold) < 1024)
		notice(nick,
		       "Invalid port specified for DCC CHAT.  Not funny.");
	      else if (!makeconn(dccbuff,nick,userhost))
		notice(nick,"DCC CHAT connection failed");
	      return;
	    }
	}
      notice(nick,"Unable to DCC CHAT.  Invalid protocol.");
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
  if( !newhashrec )
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
  prev = (struct hashrec *)NULL;

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

	  if(find->info->link_count > 0)
	    {
	      find->info->link_count--;
	      if(find->info->link_count == 0)
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
 * report_mem()
 * inputs	- socket to report to
 * output	- none
 * side effects	- rough memory usage is reported
 */
void report_mem(int sock)
{
  struct hashrec *current;
  int i;
  unsigned long total_hosttable=0L;
  int count_hosttable=0;
  unsigned long total_domaintable=0L;
  int count_domaintable=0;
  unsigned long total_iptable=0L;
  int count_iptable=0;
  unsigned long total_usertable=0L;
  int count_usertable=0;
  unsigned long total_userentry=0L;
  int count_userentry=0;

  /*  hosttable,domaintable,iptable */

  for(i=0; i < HASHTABLESIZE; i++ )
    {
      for( current = hosttable[i]; current; current = current->collision )
	{
	  total_hosttable += sizeof(struct hashrec);
	  count_hosttable++;

	  total_userentry += sizeof(struct userentry);
	  count_userentry++;
	}
    }

  for(i=0; i < HASHTABLESIZE; i++ )
    {
      for( current = domaintable[i]; current; current = current->collision )
	{
	  total_domaintable += sizeof(struct hashrec);
	  count_domaintable++;
	}
    }

#ifdef VIRTUAL
  for(i=0; i < HASHTABLESIZE; i++ )
    {
      for( current = iptable[i]; current; current = current->collision )
	{
	  total_iptable += sizeof(struct hashrec);
	  count_iptable++;
	}
    }
#endif

  for(i=0; i < HASHTABLESIZE; i++ )
    {
      for( current = usertable[i]; current; current = current->collision )
	{
	  total_usertable += sizeof(struct hashrec);
	  count_usertable++;
	}
    }

  prnt(sock,"Total hosttable memory %lu/%d entries\n",
       total_hosttable,count_hosttable);

  prnt(sock,"Total usertable memory %lu/%d entries\n",
       total_usertable,count_usertable);

  prnt(sock,"Total domaintable memory %lu/%d entries\n",
       total_domaintable,count_domaintable);

  prnt(sock,"Total iptable memory %lu/%d entries\n",
       total_iptable, count_iptable);

  prnt(sock,"Total user entry memory %lu/%d entries\n",
       total_userentry, count_userentry);

  prnt(sock,"Total memory in use %lu\n", 
       total_hosttable + total_domaintable + total_iptable + total_userentry );
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

  if( !(host = strchr(userhost,'@')) )
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
      if( !strcmp(find->info->nick,nick1) )
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
			userinfo->user,(char *)NULL))
      {
	if(config_entries.debug && outfile)
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
			(char *)NULL))
      {
	if(config_entries.debug && outfile)
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
			(char *)NULL))
      {
	if(config_entries.debug && outfile)
	  {
	    fprintf(outfile,"*** Error removing %s!%s@%s from user table!\n",
		    nick,
		    userinfo->user,
		    userinfo->host);
	  }

      }

#ifdef VIRTUAL
  /* well, no such thing as a class c , but it will do */
  if(userinfo->ip)
    strcpy(ip_class_c,userinfo->ip);
  else
    ip_class_c[0] = '\0';

  p = ip_class_c;
  found_dots = 0;
  while(*p)
    {
      if(*p == '.')
	found_dots++;

      if(found_dots == 3)
	{
	  *p = '\0';
	  break;
	}
      p++;
    }

  if(config_entries.debug && outfile)
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
			(char *)NULL))
      {
	if(config_entries.debug && outfile)
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

  if( obvious_dns_spoof( nick, userinfo ) )
    return;

  par[0] = nick;
  par[1] = userinfo->user;
  par[2] = userinfo->host;
  par[3] = userinfo->ip;
  par[4] = userinfo->class;
  for (temp=user_signon;temp;temp=temp->next)
    temp->function(doingtrace, 5, par);

  newuser = (struct userentry *)malloc(sizeof(struct userentry));
  if( !newuser )
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
  if(userinfo->ip)
    strncpy(newuser->ip_host,userinfo->ip,MAX_IP);
  else
    strcpy(newuser->ip_host,"0.0.0.0");

#ifdef VIRTUAL
  /* well, no such thing as a class c , but it will do */
  if(userinfo->ip)
    strcpy(newuser->ip_class_c,userinfo->ip);
  else
    newuser->ip_class_c[0] = '\0';

  p = newuser->ip_class_c;

  found_dots = 0;
  while(*p)
    {
      if(*p == '.')
	found_dots++;

      if(found_dots == 3)
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
  if(newuser->ip_class_c[0])
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
  if(newuser->ip_class_c[0])
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
 * obvious_dns_spoof
 *
 * inputs	- pointer to nick
 *		- pointer to userinfo
 * output	- YES if obvious spoof
 * side effects	-
 */

static int obvious_dns_spoof( char *nick, struct plus_c_info *userinfo)
{
  char *p;
  int  len;

/*
 *  *sigh* catch some obvious dns spoofs.
 * basically, at least throw off users with a top level domain
 * with more than 3 characters in it, throw off users with a '*' or '@'
 * in hostpart.
 *
 */

  if ( (p = strrchr(userinfo->host,'.')) )
    {
      p++;
      len = strlen(p);
      if(len > 3)
	{
	  suggest_action("spoof",
			     nick,
			     "<unknown>",
			     "<unknown>",
			     NO,
			     YES);
	  return YES;
	}

      if(len == 3)
	{
	  int legal_top_level=NO;

	  if(!strcasecmp(p,"net"))legal_top_level = YES;
	  if(!strcasecmp(p,"com"))legal_top_level = YES;
	  if(!strcasecmp(p,"org"))legal_top_level = YES;
	  if(!strcasecmp(p,"gov"))legal_top_level = YES;
	  if(!strcasecmp(p,"edu"))legal_top_level = YES;
	  if(!strcasecmp(p,"mil"))legal_top_level = YES;
	  if(!strcasecmp(p,"int"))legal_top_level = YES;

	  if(isdigit(*p) && isdigit(*(p+1)) && isdigit(*(p+2)) )
	     legal_top_level = YES;

	  if(!legal_top_level)
	    {
	      suggest_action(get_action_type("spoof"), nick, "<unknown>", "<unknown>", NO, YES);
	      return YES;
	    }
	}
    }

  if( (strchr(userinfo->host,'@')) )
    {
      suggest_action(get_action_type("spoof"), nick, "<unknown>", "<unknown>", NO, YES);
      return YES;
    }

  if(strchr(userinfo->host,'*'))
    {
      suggest_action(get_action_type("spoof"), nick, "<unknown>", "<unknown>", NO, YES);
      return YES;
    }

  if( (strchr(userinfo->host,'?')) )
    {
      suggest_action(get_action_type("spoof"), nick, "<unknown>", "<unknown>", NO, YES);
      return YES;
    }


#ifdef DETECT_DNS_SPOOFERS
  if(userinfo->ip && !okhost(userinfo->user, userinfo->host))
    confirm_match_ip(nick,userinfo->ip,userinfo->host);
#endif

  return NO;
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
	  if( *ip_domain == '.' )
	    found_dots++;
	  else if(!isdigit(*ip_domain))
	   {
	     is_legal_ip = NO;
	     break;
	   }

          if(found_dots == 3 )
            break;

	  ip_domain++;

          if( i > (MAX_IP-2))
            {
              is_legal_ip = NO;
              break;
            }
	}
      iphold[i++] = '*';
      iphold[i] = '\0';
      ip_domain = iphold;
    }

  if( (found_dots != 3) || !is_legal_ip)
    {
      found_domain = host + (strlen(host) - 1);

      /* find tld "com" "net" "org" or two letter domain i.e. "ca" */
      while (found_domain != host)
	{
          if(*found_domain == '.')
	    {
	      if(found_domain[3] == '\0')
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
          if(*found_domain == '.')
	    {
	      if(!two_letter_tld)
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

      if(two_letter_tld)
	{
	  while (found_domain != host)
	    {
	      if(*found_domain == '.')
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

void inithash()
{
  freehash();
  doingtrace = YES;
  toserv("TRACE\n");
}

/*
 * initopers()
 * 
 * inputs	- NONE
 * output	- NONE
 * side effects	- start determining who by default has dcc privileges
 *		  by checking the stats O list of the server.
 *
 */

void initopers(void)
{
  clear_userlist();
  load_userlist();
  toserv("STATS O\n");
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

	  if(clonecount == 1)
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

	  if(clonecount == 1)
	    last_user = find->info->user;
	  else if(clonecount == 2)
	    {
	      char *current_user;

	      if( *last_user == '~' )
		{
		  last_user++;
		}

	      current_user = find->info->user;
	      if( *current_user == '~' )
		{
		  current_user++;
		  current_identd = NO;
		}

	      if(strcmp(last_user,current_user) != 0 && current_identd)
		different = YES;

	      suggest_action(get_action_type("clones"), find->info->nick, find->info->user,
			     find->info->host, different, current_identd);
	    }

	  find->info->reporttime = now;
	  if(clonecount == 1)
	    ;
	  else if(clonecount == 2)
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

	  if(clonecount == 1)
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

	      suggest_action(get_action_type("vclones"), find->info->nick, find->info->user,
			     find->info->host, NO, NO);
	    }

	  find->info->reporttime = now;
	  if(clonecount == 1)
	    ;
	  else if(clonecount == 2)
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


/*
 * report_nick_flooders
 *
 * inputs	- socket to use
 * output	- NONE
 * side effects	- list of current nick flooders is reported
 *
 *  Read the comment in add_to_nick_change_table as well.
 *
 */

void report_nick_flooders(int sock)
{
  int i;
  int reported_nick_flooder= NO;
  time_t current_time;
  time_t time_difference;
  int time_ticks;

  if(sock < 0)
    return;

  current_time = time((time_t *)NULL);

  for( i = 0; i < NICK_CHANGE_TABLE_SIZE; i++ )
    {
      if( nick_changes[i].user_host[0] )
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
		      prnt(sock,
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
      prnt(sock, "No nick flooders found\n" );
    }
}

/*
 * report_domains
 * input	- sock
 *		- num
 * output	- NONE
 * side effects	-
 */

struct sortarray sort[MAXDOMAINS+1];

void report_domains(int sock,int num)
{
  struct hashrec *userptr;

  int inuse = 0;
  int i;
  int j;
  int maxx;
  int found;
  int foundany = NO;

  for (i=0;i<HASHTABLESIZE;i++)
    {
      for( userptr = hosttable[i]; userptr; userptr = userptr->collision )
	{
	  for (j=0;j<inuse;++j)
	    {
	      if (!strcasecmp(userptr->info->domain,sort[j].domainrec->domain))
		break;
	    }

	  if ((j == inuse) && (inuse < MAXDOMAINS))
	    {
	      sort[inuse].domainrec = userptr->info;
	      sort[inuse++].count = 1;
	    }
	  else
	    {
	      ++sort[j].count;
	    }
	}
    }
  /* Print 'em out from highest to lowest */
  for (;;)
    {
      maxx = num-1;
      found = -1;
      for (i=0;i<inuse;++i)
	if (sort[i].count > maxx)
	  {
	    found = i;
	    maxx = sort[i].count;
	  }
      if (found == -1)
	break;
      if (!foundany)
	{
	  foundany = YES;
	  prnt(sock,"Domains with most users on the server:\n");
	}

      prnt(sock,"  %-40s %3d users\n",
	   sort[found].domainrec->domain,maxx);

      sort[found].count = 0;
    }

  if (!foundany)
    {
      prnt(sock, "No domains have %d or more users.\n",num);
    }
  else
    {
      prnt(sock, "%d domains found\n", inuse);
    }
}

/*
 * report_multi()
 * 
 * inputs	- socket to print out
 * output	- NONE
 * side effects	-
 */

void report_multi(int sock,int nclones)
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
		    numfound++;	/* - zaph & Dianora :-) */
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
		  numfound++;	/* - zaph and next line*/
		  prnt(sock,
		       " %s %2d connections -- %s@%s%s {%s}\n",
		       (numfound-nclones > 2) ? "==>" :
		       "   ",numfound,userptr->info->user,
		       notip ? "*" : userptr->info->domain,
		       notip ? userptr->info->domain : "*",
		       userptr->info->class);
		}
	    }
	}
    }
  if (!foundany)    
    prnt(sock, "No multiple logins found.\n");
}


void report_vmulti(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int foundany = NO;

  nclones-=2;  /* ::sigh:: I have no idea */
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( top = userptr = iptable[i]; userptr;
	   userptr = userptr->collision )
	{
	  /* Ensure we haven't already checked this user & domain */
	  for( temp = top, numfound = 0; temp != userptr;
	       temp = temp->collision )
	    {
	      if (!strcmp(temp->info->user,userptr->info->user) &&
		  !strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
		break;
	    }

	  if (temp == userptr)
	    {
	      for( temp = temp->collision; temp; temp = temp->collision )
		{
		  if (!strcmp(temp->info->user,userptr->info->user) &&
		      !strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
		    numfound++;	/* - zaph & Dianora :-) */
		}

	      if ( numfound > nclones )
		{
		  if (!foundany)
		    {
		      foundany = YES;
		      prnt(sock, 
			   "Multiple clients from the following userhosts:\n");
		    }
		  numfound++;	/* - zaph and next line*/
		  prnt(sock,
		       " %s %2d connections -- %s@%s* {%s}\n",
		       (numfound-nclones > 2) ? "==>" :
		       "   ",numfound,userptr->info->user,
		       userptr->info->ip_class_c,
		       userptr->info->class);
		}
	    }
	}
    }
  if (!foundany)    
    prnt(sock, "No multiple logins found.\n");
}

/*
 * report_multi_host()
 * 
 * inputs	- socket to print out
 * output	- NONE
 * side effects	-
 */

void report_multi_host(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int foundany = NO;
#ifdef DEBUGMODE
  placed;
#endif

  nclones-=2;
  for (i=0;i<HASHTABLESIZE;++i)
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
		    numfound++;	/* - zaph & Dianora :-) */
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
 * report_multi_user()
 * 
 * inputs	- socket to print out
 * output	- NONE
 * side effects	-
 */

void report_multi_user(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound;
  int i;
  int foundany = NO;
#ifdef DEBUGMODE
  placed;
#endif

  nclones-=2;
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
	      numfound=1;	/* fixed minor boo boo -bill */
	      for( temp = temp->collision; temp; temp = temp->collision )
		{
		  if (!strcmp(temp->info->user,userptr->info->user))
		    numfound++;	/* - zaph & Dianora :-) */
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
 * inputs	- socket to print out
 *              - number to consider as clone
 * output	- NONE
 * side effects	-
 */

void report_multi_virtuals(int sock,int nclones)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int numfound;
  int i;
  int foundany = 0;

  if(!nclones)
    nclones = 3;

  nclones-=2;
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
		    numfound++;	/* - zaph & Dianora :-) */
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
 * check_clones
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	-
 *		  check for "unseen" clones, i.e. ones that have
 *		  crept onto the server slowly
 */

void check_clones(void)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int numfound;
  int i;
  int notip;

  for (i=0; i < HASHTABLESIZE; i++)
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
		    numfound++;	/* - zaph & Dianora :-) */
		}
	      if (numfound > MIN_CLONE_NUMBER)
		{
		  notip = strncmp(userptr->info->domain,userptr->info->host,
				  strlen(userptr->info->domain)) ||
		    (strlen(userptr->info->domain) == 
		     strlen(userptr->info->host));

		  sendtoalldcc(SEND_WARN_ONLY,
				"clones> %2d connections -- %s@%s%s {%s}\n",
				numfound,userptr->info->user,
				notip ? "*" : userptr->info->domain,
				notip ? userptr->info->domain : "*",
				userptr->info->class);
		}
	    }
	}
    }
}


/*
 * list_nicks()
 *
 * inputs	- socket to reply on, nicks to search for
 * output	- NONE
 * side effects	-
 */

void list_nicks(int sock,char *nick)
{
  struct hashrec *userptr;
  int i;
  int numfound=0;

  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( userptr = domaintable[i]; userptr; userptr = userptr->collision )
	{
	  if (!wldcmp(nick,userptr->info->nick))
	    {
	      if(!numfound)
		{
		  prnt(sock,
		       "The following clients match %.150s:\n",nick);
		}
	      numfound++;

	      prnt(sock,
		   "  %s (%s@%s)\n",
		   userptr->info->nick,
		   userptr->info->user,userptr->info->host);
	    }
        }
    }

  if (numfound)
    prnt(sock,
	 "%d matches for %s found\n",numfound,nick);
  else
    prnt(sock,
	 "No matches for %s found\n",nick);
}

/*
 * list_class()
 * 
 * inputs	- integer socket to reply on
 *		- integer class to search for
 *		- integer show total only YES/NO
 * output	- NONE
 * side effects	-
 */

void list_class(int sock,char *class_to_find,int total_only)
{
  struct hashrec *userptr;
  int i;
  int num_found=0;
  int num_unknown=0;

  for ( i=0; i < HASHTABLESIZE; ++i )
    {
      for( userptr = domaintable[i]; userptr; userptr = userptr->collision )
	{
	  if(!strcmp(userptr->info->class, "unknown"))
	    num_unknown++;

	  if (!strcasecmp(class_to_find, userptr->info->class))
	    {
	      if(!num_found++)
		{
		  if(!total_only)
		    {
		      prnt(sock,
			   "The following clients are in class %s\n",
			   class_to_find);
		    }
		}
	      if(!total_only)
		{
		  prnt(sock,
		       "  %s (%s@%s)\n",
		       userptr->info->nick,
		       userptr->info->user,userptr->info->host);
		}
	    }
        }
    }

  if (num_found)
    prnt(sock,
	 "%d are in class %s\n", num_found, class_to_find );
  else
    prnt(sock,
	 "Nothing found in class %s\n", class_to_find );
  prnt(sock,"%d unknown class\n", num_unknown);
}

/*
 * list_users()
 *
 * inputs	- socket to reply on
 * output	- NONE
 * side effects	-
 */

void list_users(int sock,char *userhost)
{
  struct hashrec *userptr;
  char fulluh[MAX_HOST+MAX_DOMAIN];
  int i;
  int numfound = 0;

  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    prnt(sock,
	 "Listing all users is not recommended.  To do it anyway, use 'list ?*@*'.\n");
  else
    {
      for (i=0;i<HASHTABLESIZE;++i)
	{
	  for( userptr = domaintable[i]; userptr;
	       userptr = userptr->collision )
	    {
	      (void)snprintf(fulluh,sizeof(fulluh) - 1,
			    "%s@%s",userptr->info->user,userptr->info->host);
	      if (!wldcmp(userhost,fulluh))
		{
		  if (!numfound++)
		    {
		      prnt(sock,
			   "The following clients match %.150s:\n",userhost);
		    }
		  if (userptr->info->ip_host[0] > '9' ||
		      userptr->info->ip_host[0] < '0')
		    prnt(sock,
			 "  %s (%s) {%s}\n",
			 userptr->info->nick,
			 fulluh, userptr->info->class);
		  else
		    prnt(sock, "  %s (%s) [%s] {%s}\n",
			 userptr->info->nick,
			 fulluh, userptr->info->ip_host,
			 userptr->info->class);
		}
	    }
	}
      if (numfound > 0)
	prnt(sock,
	     "%d matches for %s found\n",numfound,userhost);
      else
	prnt(sock,
	     "No matches for %s found\n",userhost);
  }
}

/*
 * list_virtual_users()
 *
 * inputs	- socket to reply on
 *	        - ip block to match on
 * output	- NONE
 * side effects	-
 */

void list_virtual_users(int sock,char *userhost)
{
  struct hashrec *ipptr;
  int i,numfound = 0;

  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    prnt(sock,
	 "Listing all users is not recommended.  To do it anyway, use 'list ?*@*'.\n");
  else
    {
      for ( i=0; i < HASHTABLESIZE; ++i)
	{
	  for( ipptr = iptable[i]; ipptr; ipptr = ipptr->collision )
	    {
	      if (!wldcmp(userhost,ipptr->info->ip_host))
		{
		  if (!numfound++)
		    {
		      prnt(sock,
			   "The following clients match %.150s:\n",userhost);
		    }
		  prnt(sock,
		       "  %s [%s] (%s@%s) {%s}\n",
		       ipptr->info->nick,
		       ipptr->info->ip_host,
		       ipptr->info->user,ipptr->info->host,
		       ipptr->info->class);
		}
	    }
	}
      if (numfound > 0)
	prnt(sock,
	     "%d matches for %s found\n",numfound,userhost);
      else
	prnt(sock,
	     "No matches for %s found\n",userhost);
    }
}

/*
 *  ok, I redid the redo of the list_user code.  There was a random buffer
 *  problem somewhere that I couldn't track down for the life of me.
 *
 *		-bill
 */
void kill_list_users(int sock,char *userhost, char *reason)
{
  struct hashrec *userptr;
  /* Looks fishy but it really isn't */
  char fulluh[MAX_HOST+MAX_DOMAIN];
  int i;
  int numfound = 0;

  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
      prnt(sock, "Let's not kill all the users.\n");
  else
    {
      for (i=0;i<HASHTABLESIZE;++i)
	{
	  for( userptr = domaintable[i]; userptr;
	       userptr = userptr->collision )
	    {
	      (void)snprintf(fulluh,sizeof(fulluh) - 1,
			    "%s@%s",userptr->info->user,userptr->info->host);
	      if (!wldcmp(userhost,fulluh))
		{
		  if (!numfound++)
		    {
			log("listkilled %s\n", fulluh);
		    }
		  toserv("KILL %s :%s\n", userptr->info->nick, reason);
		}
	    }
	}
      if (numfound > 0)
	prnt(sock,
	     "%d matches for %s found\n",numfound,userhost);
      else
	prnt(sock,
	     "No matches for %s found\n",userhost);
  }
}

/*
 * print_help()
 *
 * inputs	- socket, help_text to use
 * output	- none
 * side effects	- prints help file to user
 */

void print_help(int sock,char *text)
{
  FILE *userfile;
  char line[MAX_BUFF];
  char help_file[MAX_BUFF];

  if(!text)
    {
      if( !(userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) )
	{
	  prnt(sock,"Help is not currently available\n");
	  return;
	}
    }
  else
    {
      while(*text == ' ')
	text++;

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( !(userfile = fopen(help_file,"r")) )
	{
	  prnt(sock,"Help for %s is not currently available\n",text);
	  return;
	}
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      prnt(sock, "%s", line);
    }
  fclose(userfile);
}

/*
 * print_motd()
 *
 * inputs	- socket
 * output	- none
 * side effects	- prints a message of the day to the connecting client
 *
 * Larz asked for this one. a message of the day on connect
 * I just stole the code from print_help
 */

void print_motd(int sock)
{
  FILE *userfile;
  char line[MAX_BUFF];

  if( !(userfile = fopen(MOTD_FILE,"r")) )
    {
      prnt(sock,"No MOTD\n");
      return;
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      prnt(sock, "%s", line);
    }
  fclose(userfile);
}

void report_failures(int sock,int num)
{
  int maxx;
  int foundany = NO;
  struct failrec *tmp;
  struct failrec *found;

  /* Print 'em out from highest to lowest */
  FOREVER
    {
      maxx = num-1;
      found = NULL;

      for (tmp = failures; tmp; tmp = tmp->next)
	{
	  if (tmp->failcount > maxx)
	    {
	      found = tmp;
	      maxx = tmp->failcount;
	    }
	}

      if (!found)
	break;

      if (!foundany++)
	{
	  prnt(sock, "Userhosts with most connect rejections:\n");
	  prnt(sock," %5d rejections: %s@%s%s\n", found->failcount,
	       (*found->user ? found->user : "<UNKNOWN>"), found->host,
	       (found->botcount ? " <BOT>" : ""));
	}
      found->failcount = -found->failcount;   /* Yes, this is horrible */
    }

  if (!foundany)
    {
      prnt(sock,"No userhosts have %d or more rejections.\n",num);
    }

  for( tmp = failures; tmp; tmp = tmp->next )
    {
      if (tmp->failcount < 0)
	tmp->failcount = -tmp->failcount;   /* Ugly, but it works. */
    }
}

/*
 * report_clones
 *
 * inputs	- socket to report on
 * output	- NONE
 * side effects	- NONE
 */

void report_clones(int sock)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int  numfound;
  int i;
  int j;
  int k;
  int foundany = NO;
  time_t connfromhost[MAXFROMHOST];
  
  if(sock < 0)
    return;

  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( top = userptr = hosttable[i]; userptr; userptr = userptr->collision)
	{
	  /* Ensure we haven't already checked this host */
	  for( temp = top, numfound = 0; temp != userptr;
	       temp = temp->collision )
	    {
	      if (!strcmp(temp->info->host,userptr->info->host))
		break;
	    }

	  if (temp == userptr)
	    {
	      connfromhost[numfound++] = temp->info->connecttime;
	      for( temp = temp->collision; temp; temp = temp->collision )
		{
		  if (!strcmp(temp->info->host,userptr->info->host) &&
		      numfound < MAXFROMHOST)
		    connfromhost[numfound++] = temp->info->connecttime;
		}

	      if (numfound > 2)
		{
		  for (k=numfound-1;k>1;--k)
		    {
		      for (j=0;j<numfound-k;++j)
			{
			  if (connfromhost[j] &&
			      connfromhost[j] - connfromhost[j+k] <= (k+1)
			      * CLONEDETECTINC)
			    goto getout;  /* goto rules! */
			}
		    }
		getout:

		  if (k > 1)
		    {
		      if (!foundany)
			{
			    prnt(sock, 
				 "Possible clonebots from the following hosts:\n");
			  foundany = YES;
			}
			prnt(sock,
			     "  %2d connections in %3d seconds (%2d total) from %s\n",
			     k+1,
			     connfromhost[j] - connfromhost[j+k],
			     numfound+1,
			     userptr->info->host);
		    }
		}
	    }
	}
    }

  if (!foundany)
    {
	prnt(sock, "No potential clonebots found.\n");
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

  current_time = time((time_t *)NULL);
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
		      if (!strncasecmp(config_entries.cflood_act, "dline", 5))
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

  current_time = time((time_t *)NULL);

  p = strstr(server_notice,"requested by");

  if(!p)
    return;

  nick_reported = p + 13;

  if((p = strchr(nick_reported,' ')))
    *p = '\0';
  else
    return;
  p++;

  user_host = p;
/*
 *  Lets try and get it right folks... [user@host] or (user@host)
 */

  if(*user_host == '[')
    {
      user_host++;
      if( (p = strrchr(user_host,']')) )
	*p = '\0';
    }
  else if(*user_host == '(')
    {
      user_host++;
      if( (p = strrchr(user_host,')')) )
	*p = '\0';
    }

  s = user_host;
  d = user;
  n = MAX_NICK;
  while(*s)
    {
      if(*s == '@')
	break;
      *d++ = *s++;
      n--;
      if(n == 0)
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
      if(n == 0)
	break;
    }
  *d = '\0';
  
  /* Don't even complain about opers */

  sendtoalldcc(SEND_LINK_ONLY,
	       "[LINKS] by %s (%s@%s)\n",
	       nick_reported, user, host ); /* - zaph */

  if ( isoper(user,host) )  
    {
      if(config_entries.debug && outfile)
	{
	  (void)fprintf(outfile, "DEBUG: is oper\n");
	}
      return;
    }


  for(i = 0; i < MAX_LINK_LOOKS; i++ )
    {
      if(link_look[i].user_host[0])
	{
	  if(!strcasecmp(link_look[i].user_host,user_host))
	    {
	      found_entry = YES;
	  
	      /* if its an old old entry, let it drop to 0, then start counting
	       * (this should be very unlikely case)
	       */

	      if((link_look[i].last_link_look + MAX_LINK_TIME) < current_time)
		{
		  link_look[i].link_look_count = 0;
		}

	      link_look[i].link_look_count++;
	      
	      if(link_look[i].link_look_count >= MAX_LINK_LOOKS)
		{
		  sendtoalldcc(SEND_WARN_ONLY,
			       "possible LINK LOOKER nick [%s]\n", 
			       nick_reported,user_host);

		  log("possible LINK LOOKER  = %s [%s]\n",
		      nick_reported,user_host);

/*
 * Changed code to conform to clone_act
 * -bill
 */
		  if ( !okhost(user,host) )
		    {
		      if(*user == '~')
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
	      if((link_look[i].last_link_look + MAX_LINK_TIME) < current_time)
		{
		  link_look[i].user_host[0] = '\0';
		}
	    }
	}
      else
	{
	  if(first_empty_entry < 0)
	    first_empty_entry = i;
	}
    }

/*
 *  If this is a new entry, then found_entry will still be NO
 */

  if(!found_entry)
    {
      if(first_empty_entry >= 0)
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

  if( !(nick = strtok(server_notice," ")) )
    return;

  if( !(user_host = strtok((char *)NULL," ")) )
    return;

  if(*user_host == '[')
    *user_host++;
  if( !(p = strrchr(user_host,']')) )
    return;
  *p = '\0';		

  user = user_host;	
  if( !(p = strchr(user_host,'@')) )
    return;
  *p = '\0';

  host = p;	
  host++;

  sendtoalldcc(SEND_WARN_ONLY,"%s bot [%s!%s@%s]",
	       type_of_bot,
	       nick,	
	       user,
	       host);

  suggest_action(get_action_type("bots"), nick, user, host, NO, YES);

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

  if( !(nick_reported = strtok(server_notice," ")) )
    return;

  if( !(user_host = strtok((char *)NULL," ")) )
    return;

/*
 * Lets try and get it right folks... [user@host] or (user@host)
 */

  if(*user_host == '[')
    {
      user_host++;
      if( (p = strrchr(user_host,']')) )
	*p = '\0';
    }
  else if(*user_host == '(')
    {
      user_host++;
      if( (p = strrchr(user_host,')')) )
	*p = '\0';
    }

  sendtoalldcc(SEND_WARN_ONLY, "CS nick flood user_host = [%s]", user_host);

  log("CS nick flood user_host = [%s]\n", user_host);


  if( !(user = strtok(user_host,"@")) )
    return;

  if( !(host = strtok((char *)NULL,"")) )
    return;

  if ( (!okhost(user,host)) && (!isoper(user,host)) )  
    {
      if(*user_host == '~')
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

  if( !(strtok(server_notice," ") == NULL) )
    return;

  if( !(user_host = strtok((char *)NULL," ")) )
    return;

  if(*user_host == '[')
    {
      user_host++;
      if( (p = strrchr(user_host,']')) )
	*p = '\0';
    }
  else if(*user_host == '(')
    {
      user_host++;
      if( (p = strrchr(user_host,')')) )
	*p = '\0';
    }

  sendtoalldcc(SEND_WARN_ONLY, "CS clones user_host = [%s]\n", user_host);
  log("CS clones = [%s]\n", user_host);

  user = user_host;

  if(*user == '~')
    {
      user++;
      identd = NO;
    }

  if( !(host = strchr(user_host,'@')) )
    return;

  *host = '\0';
  host++;

  suggest_action(get_action_type("clones"), "", user, host, NO, identd);
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

  if( !(p = strtok(server_notice," ")) )	/* Throw away the "From" */
    return;

  if(strcasecmp(p,"From"))	/* This isn't an LT notice */
    {
      nick1 = p;	/* This _should_ be nick1 */

      if( !(user_host = strtok((char *)NULL," ")) )	/* (user@host) */
	return;

      if(*user_host == '(')
	user_host++;

      if( (p = strrchr(user_host,')')) )
	*p = '\0';

      if( !(p = strtok((char *)NULL," ")) )
	return;

      if(strcmp(p,"now") != 0 )
	return;

      if( !(p = strtok((char *)NULL," ")) )
	return;

      if(strcmp(p,"known") != 0 )
	return;

      p = strtok((char *)NULL," ");
      if(p == (char *)NULL)
	return;

      if(strcmp(p,"as"))
	return;

      if( !(nick2 = strtok((char *)NULL," ")) )
	return;

      add_to_nick_change_table(user_host,nick2);
      updateuserhost(nick1,nick2,user_host);

      return;
    }

  if( !(nick1 = strtok((char *)NULL," ")) )
    return;

  if( !(p = strtok((char *)NULL," ")) )	/* Throw away the "to" */
    return;

  if( !(nick2 = strtok((char *)NULL," ")) )	/* This _should_ be nick2 */
    return;

  if( !(user_host = strtok((char *)NULL," ")) )	/* u@h  */
    return;

  if(*user_host == '[')
    user_host++;

  if( (p = strrchr(user_host,']')) )
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

  current_time = time((time_t *)NULL);

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
    {
      if( nick_changes[i].user_host[0] )
	{
	  time_t time_difference;
	  int time_ticks;

	  time_difference = current_time - nick_changes[i].last_nick_change;

	  /* is it stale ? */
	  if( time_difference >= NICK_CHANGE_T2_TIME )
	    {
	      nick_changes[i].user_host[0] = '\0';
	      nick_changes[i].noticed = NO;
	    }
	  else
	    {
	      /* how many 10 second intervals do I have? */
	      time_ticks = time_difference / NICK_CHANGE_T1_TIME;

	      /* is it stale? */
	      if(time_ticks >= nick_changes[i].nick_change_count)
		{
		  nick_changes[i].user_host[0] = '\0';
		  nick_changes[i].noticed = NO;
		}
	      else
		{
		  /* just decrement 10 second units of nick changes */
		  nick_changes[i].nick_change_count -= time_ticks;

		  if( !(strcasecmp(nick_changes[i].user_host,user_host)) )
		    {
		      nick_changes[i].last_nick_change = current_time;
		      (void)strncpy(nick_changes[i].last_nick,
				    last_nick,MAX_NICK);
		      nick_changes[i].nick_change_count++;
		    }

		  /* now, check for a nick flooder */
	  
		  if((nick_changes[i].nick_change_count >=
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


		      if( !(user = strtok(user_host,"@")) )
			return;
		      if( !(host = strtok((char *)NULL,"")) )
			return;
		      
		      if(*user_host == '~')
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
	  if( found_empty_entry < 0 )
	    found_empty_entry = i;
	}
    }

/* If the table is full, don't worry about this nick change for now
 * if this nick change is part of a flood, it will show up
 * soon enough anyway... -db
 */

  if(found_empty_entry > 0)
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

      if( !(text = strchr(text,' ')) )
	return;

      p = strstr(text+1,"(Single");
      if(p)
	{
	  while(p != text)
	    {
	      if(*p == ']')
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
	  if( !(text = strchr(text+1,' ')) )
	    return;
	}

      logfailure(text+1,1);
    }
}


/*
 * freehash()
 * 
 * inputs		- NONE
 * output		- NONE
 * side effects 	- clear all allocated memory hash tables
 * 
*/

void freehash(void)
{
  struct hashrec *ptr;
  int i;

  for (i=0;i<HASHTABLESIZE;i++)
    {
      ptr = usertable[i];
      free_hash_links(ptr);
      usertable[i] = (struct hashrec *)NULL;

      ptr = hosttable[i];
      free_hash_links(ptr);
      hosttable[i] = (struct hashrec *)NULL;

      ptr = domaintable[i];
      free_hash_links(ptr);
      domaintable[i] = (struct hashrec *)NULL;

#ifdef VIRTUAL
      ptr = iptable[i];
      free_hash_links(ptr);
      iptable[i] = (struct hashrec *)NULL;
#endif
    }

  for(i = 0; i < NICK_CHANGE_TABLE_SIZE; i++)
    {
      nick_changes[i].user_host[0] = '\0';
      nick_changes[i].noticed = NO;
    }
}

/*
 * free_hash_links
 *
 * inputs	- pointer to link list to free
 * output	- none
 * side effects	-
 */
static void free_hash_links(struct hashrec *ptr)
{
  struct hashrec *next_ptr;

  while( ptr )
    {
      next_ptr = ptr->collision;

      if(ptr->info->link_count > 0)
	ptr->info->link_count--;

      if(ptr->info->link_count == 0)
	{
	  (void)free(ptr->info); 
	}

      (void)free(ptr);
      ptr = next_ptr;
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

  if( !(nick = strstr(server_notice,"by")) )
    return;

  nick += 3;

  if( (p = strchr(nick, ' ')) )
    *p = '\0';
  p++;

  fulluh = p;
  if(*fulluh == '(')
    fulluh++;

  if( (p = strchr(fulluh, ')' )) )
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
	  if(connections[i].type & TYPE_TCM)
	    continue;

	  /* ignore invisible users/opers */
	  if( connections[i].type & (TYPE_INVS|TYPE_INVM))
	    continue;

	  /* display opers */
	  if( connections[i].type & TYPE_OPER)
	    {
#ifdef HIDE_OPER_HOST
              notice(nick,
                     "%s - idle %lu\n",
                     connections[i].nick,
                     time((time_t *)NULL) - connections[i].last_message_time );
#else 
	      notice(nick,
		     "%s (%s@%s) idle %lu\n",
		     connections[i].nick,
		     connections[i].user,
		     connections[i].host,
		     time((time_t *)NULL) - connections[i].last_message_time );
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

static void _reload(int connnum, int argc, char *argv[])
{
 initopers();
 inithash();
}

static void _modinit()
{
  add_common_function(F_RELOAD, _reload);
  add_common_function(F_SERVER_NOTICE, onservnotice);
  memset(&usertable,0,sizeof(usertable));
  memset(&hosttable,0,sizeof(usertable));
  memset(&domaintable,0,sizeof(usertable));
#ifdef VIRTUAL
  memset(&iptable,0,sizeof(iptable));
#endif
  memset(&nick_changes,0,sizeof(nick_changes));
  init_link_look_table();
}
