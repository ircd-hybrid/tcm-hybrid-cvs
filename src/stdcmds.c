/************************************************************
* stdcmds.c                                                 *
*   Simple interfaces to send out most types of IRC messages*
*   Contains interface to msg an entire file to a user      *
* Includes routines:                                        *
*   void op                                                 *
*   void join                                               *
*   void leave                                              *
*   void notice                                             *
*   void msg                                                *
*   void newnick                                            *
*   void get_userhost                                       *
*   void privmsg                                            *
************************************************************/

/* $Id: stdcmds.c,v 1.70 2002/05/25 16:14:36 jmallett Exp $ */

#include "setup.h"

#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "logging.h"
#include "serverif.h"
#include "stdcmds.h"
#include "userlist.h"
#include "wild.h"
#include "match.h"

#ifdef HAVE_REGEX_H
#include <regex.h>
#define REGCOMP_FLAGS REG_EXTENDED
#define REGEXEC_FLAGS 0
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned int) 0xffffffff)
#endif

int doingtrace = NO;
void freehash(void);

/*
 * free_hash_links
 *
 * inputs       - pointer to link list to free
 * output       - none
 * side effects -
 */
static void 
free_hash_links(struct hashrec *ptr)
{
  struct hashrec *next_ptr;

  while(ptr != NULL)
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
 * freehash()
 *
 * inputs               - NONE
 * output               - NONE
 * side effects         - clear all allocated memory hash tables
 *
*/

void 
freehash(void)
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



/* The following are primitives that send messages to the server to perform
 * certain things.  The names are quite self explanatory, so I am not going
 * to document each.  By no means are they complex.
 */

void
oper()
{
  print_to_server("OPER %s %s",
          config_entries.oper_nick_config,
          config_entries.oper_pass_config);
}

void
op(char *chan,char *nick)
{
  print_to_server("MODE %s +o %s", chan, nick);
}

void
join(char *chan, char *key)
{
  if ((chan == NULL) || (*chan == '\0'))
    return;
  if (key != NULL)
    print_to_server("JOIN %s %s", chan, key);
  else
    print_to_server("JOIN %s", chan);
}

void
set_modes(char *chan, char *mode, char *key)
{
  if ((chan == NULL) || (*chan == '\0'))
    return;
  if (mode != NULL)
  {
    if (key != NULL)
      print_to_server("MODE %s +%sk %s", chan, mode, key);
    else
      print_to_server("MODE %s +%s", chan, mode);
  }
  else
  {
    if (key != NULL)
      print_to_server("MODE %s +k %s", chan, key);
  }
}

void
leave(char *chan)
{
  print_to_server("PART %s", chan);
}


void
newnick(char *nick)
{
  print_to_server("NICK %s", nick);
}

/*
 * msg_mychannel
 *
 * inputs       - format varargs
 * output       - none
 * side effects -
 */

void
msg_mychannel(char *format, ...)
{
  va_list va;
  char message[MAX_BUFF];

  va_start(va,format);

  vsprintf(message, format, va );

  privmsg(config_entries.defchannel,message);

  va_end(va);
}

/*
 * Generic report
 *
 * report
 *
 * inputs       -
 * output       - NONE
 * side effects
 */

void 
report(int type, int channel_send_flag, char *format,...)
{
  char msg[MAX_BUFF];
  va_list va;

  va_start(va,format);
  vsnprintf(msg, sizeof(msg)-2,format,va);

  /* Probably not a format string bug, but I'm calling it this way
  ** for safety sake - Hwy
  */
  send_to_all(type, "%s",msg);

  if( channel_send_flag & config_entries.channel_report )
    {
      msg_mychannel("%s", msg);
    }

  va_end(va);
}

/*
 * find_nick
 *
 * Returns a hashrec for the given nick, or NULL if not found
 *
 */
struct hashrec * find_nick(char * nick) {
  int i;
  struct hashrec * userptr;
  if (!nick)
    return NULL;
  for (i=0;i<HASHTABLESIZE;++i) {
    for( userptr = domaintable[i]; userptr; userptr = userptr->collision ) {
      if (!wldcmp(nick, userptr->info->nick))
	return userptr;
    }
  }
  return NULL;
}

/*
 * find_host
 *
 * Returns first hashrec for the given host, or NULL if not found
 *
 */
struct hashrec * find_host(char * host) {
  int i;
  struct hashrec * userptr;
  if (!host)
    return NULL;
  for (i=0;i<HASHTABLESIZE;++i) {
    for( userptr = domaintable[i]; userptr; userptr = userptr->collision ) {
      if (!wldcmp(host, userptr->info->host))
	return userptr;
    }
  }
  return NULL;
}


/*
 * handle_action
 *
 * Replaces suggest_action. Uses configured actions and methods to
 * handle a reported event. 
 * 
 * This function does all reporting to DCC and channels, as configured
 * per action.
 * 
 * Note that if an ip is passed, it *must* be a valid ip, no checks for that
 */

void
handle_action(int actionid, int idented, char *nick, char *user,
	      char *host, char *ip, char * addcmt)
{
  char newhost[MAX_HOST];
  char newuser[MAX_USER];
  char comment[512];
  char *p;
  struct hashrec * userptr;

  if (!user && !host && nick)
    {
      userptr = find_nick(nick);
      if (userptr)
	{
	  user = userptr->info->user;
	  host = userptr->info->host;
	  ip = userptr->info->ip_host;
	  if (!strcmp(ip, "255.255.255.255"))
	    ip = 0;
	}
    }

  /* Sane input? */
  if ((actionid < 0) || (actionid >= MAX_ACTIONS) ||
      !user || !host || !host[0] ||
      strchr(host, '*') || strchr(host, '?') ||
      strchr(user, '*') || strchr(user, '?')) 
    {
      if ((actionid < 0) || (actionid >= MAX_ACTIONS))
	log("handle_action: action is %i\n", actionid);
      else if (!user)
	log("handle_action(%s): user is NULL\n", actions[actionid].name);
      else if (!host)
	log("handle_action(%s): host is NULL\n", actions[actionid].name);
      else if (!host[0])
	log("handle_action(%s): host is empty\n", actions[actionid].name);
      else if (strchr(host, '*') || strchr(host, '?'))
	log("handle_action(%s): host contains wildchars (%s)\n",
	    actions[actionid].name, host);
      else if (strchr(user, '*') || strchr(user, '?'))
	log("handle_action(%s): user contains wildchars (%s)\n",
	    actions[actionid].name, user);
      return;
    }

  /* Valid action? */
  if (!actions[actionid].method)
    {
      log("handle_action(%s): method field is 0\n", actions[actionid].name);
      return;
    }

  /* Use hoststrip to create a k-line mask.
   * First the host
   */
  switch (actions[actionid].hoststrip & HOSTSTRIP_HOST)
    {
    case HOSTSTRIP_HOST_BLOCK:
      if (inet_addr(host) == INADDR_NONE) {
	p = host;
	while (*p && (*p != '.'))
	  p++;
	if (!*p)
	  {
	    /* Host without dots?  */
	    strncpy(newhost, host, sizeof(newhost));
	    newhost[sizeof(newhost)-1] = 0;
	    log("handle_action(%s): '%s' appears to be a weird host\n",
		actions[actionid].name, host);
	    return;
	  }
	newhost[0] = '*';
	newhost[1] = 0;
	strncat(newhost, host, sizeof(newhost));
      }
      else
	{
	  strncpy(newhost, host, sizeof(newhost)-3);
	  /* This HAS to be useless, but oh well.*/
	  newhost[sizeof(newhost)-4] = 0;
	  p = strrchr(newhost, '.');
	  if (*p)
	    {
	      p[1] = '*';
	      p[2] = 0;
	    }
	}
      break;
    case HOSTSTRIP_HOST_AS_IS:
    default:
      strncpy(newhost, host, sizeof(newhost));
      newhost[sizeof(newhost)-1] = 0;
      break;
    }

  if (idented)
    {
      switch(actions[actionid].hoststrip & HOSTSTRIP_IDENT)
	{
	case HOSTSTRIP_IDENT_PREFIXED:
	  p = user;
	  if (strlen(p)>8) 
	    p += strlen(user)-8;
	  strncpy(newuser+1, p, sizeof(newuser)-1);
	  newuser[0] = '*';
	  newuser[sizeof(newuser)-1] = 0;
	  break;
	case HOSTSTRIP_IDENT_ALL:
	  strcpy(newuser, "*");
	  break;
	case HOSTSTRIP_IDENT_AS_IS:
	default:
	  strncpy(newuser, user, sizeof(newuser));
	  newuser[sizeof(newuser)-1] = 0;
	  break;
	}
    }
  else
    {
      switch(actions[actionid].hoststrip & HOSTSTRIP_NOIDENT)
	{
	case HOSTSTRIP_NOIDENT_PREFIXED:
	  p = user;
	  if (strlen(p)>8)
	    p += strlen(user)-8;
	  strncpy(newuser+1, user, sizeof(newuser)-1);
	  newuser[0] = '*';
	  newuser[sizeof(newuser)-1] = 0;
	  break;
	case HOSTSTRIP_NOIDENT_ALL:
	  strcpy(newuser, "~*");
	  break;
	case HOSTSTRIP_NOIDENT_UNIDENTED:
	default:
	  strcpy(newuser, "*~*");
	  break;
	}
    }
  strcpy(comment, "No actions taken");


  if (!okhost(user[0] ? user : "*", host, actionid))
    {
      /* Now process the event, we got the needed data */
      if (actions[actionid].method & METHOD_TKLINE)
	{    
	  /* In case the actions temp k-line time isnt set, set a default */
	  if (actions[actionid].klinetime<=0) 
	    actions[actionid].klinetime = 60;
	  else if (actions[actionid].klinetime>14400) 
	    actions[actionid].klinetime = 14400;
	  print_to_server("KLINE %d %s@%s :%s",
		 actions[actionid].klinetime, newuser, newhost, 
		 actions[actionid].reason ?
		 actions[actionid].reason : "Automated temporary K-Line");    
	  snprintf(comment, sizeof(comment),
		   "%d minutes temporary k-line of %s@%s",
		   actions[actionid].klinetime, newuser, newhost);
	}
      else if (actions[actionid].method & METHOD_KLINE)
	{
	  print_to_server("KLINE %s@%s :%s", newuser, newhost, 
		 actions[actionid].reason ? 
		 actions[actionid].reason : "Automated K-Line");    
	  snprintf(comment, sizeof(comment),
		   "Permanent k-line of %s@%s", newuser, newhost);
	}
      else if (actions[actionid].method & METHOD_DLINE)
	{
	  if ((inet_addr(host) == INADDR_NONE) && (!ip))
	    {
	      /* We don't have any IP, so look it up from our tables */
	      userptr = find_host(host);
	      if (!userptr || !userptr->info || !userptr->info->ip_host[0])
		{
		  /* We couldn't find one either, revert to a k-line */
		  log("handle_action(%s): Reverting to k-line, couldn't find IP for %s\n",
		      actions[actionid].name, host);
		  actions[actionid].method |= METHOD_KLINE;
		  handle_action(actionid, idented, nick, user, 
				host, 0, addcmt);
		  actions[actionid].method &= ~METHOD_KLINE;
		  return;
		}
	      handle_action(actionid, idented, nick, user,
			    host, userptr->info->ip_host, addcmt);
	      return;
	    }
	  if (inet_addr(host) == INADDR_NONE)
	    {
	      /* Oks, passed host isn't in IP form.
	       * Let's move the passed ip to newhost, then mask it if needed
	       */
	      strcpy(newhost, ip);
	      if ((actions[actionid].hoststrip & HOSTSTRIP_HOST)
		  == HOSTSTRIP_HOST_BLOCK) {
		p = strrchr(newhost, '.');
		p++;
		strcpy(p, "*");
	      }
	    }

	  print_to_server("DLINE %s :%s", newhost, 
		 actions[actionid].reason ?
		 actions[actionid].reason : "Automated D-Line");    
	  snprintf(comment, sizeof(comment), "D-line of %s", newhost);    
	}
    }
  else
    {
      return;
    }

  if (actions[actionid].method & METHOD_DCC_WARN)
    {
      if (addcmt && addcmt[0])
	send_to_all(SEND_WARN,
		     "*** %s violation (%s) from %s (%s@%s): %s", 
		     actions[actionid].name, addcmt,
		     (nick && nick[0]) ? nick : "<unknown>", 
		     (user && user[0]) ? user : "<unknown>",
		     host, comment);
      else
	send_to_all(SEND_WARN,
		     "*** %s violation from %s (%s@%s): %s", 
		     actions[actionid].name, 
		     (nick && nick[0]) ? nick : "<unknown>", 
		     (user && user[0]) ? user : "<unknown>",
		     host, comment);

    }
  if (actions[actionid].method & METHOD_IRC_WARN)
    {
      if (addcmt && addcmt[0])
	msg_mychannel("*** %s violation (%s) from %s (%s@%s): %s\n",
		      actions[actionid].name, addcmt,
		      (nick && nick[0]) ? nick : "<unknown>", 
		      (user && user[0]) ? user : "<unknown>",
		      host, comment);
      else
	msg_mychannel("*** %s violation from %s (%s@%s): %s\n",
		      actions[actionid].name, 
		      (nick && nick[0]) ? nick : "<unknown>", 
		      (user && user[0]) ? user : "<unknown>",
		      host, comment);
    }
}
		  

/*
 * format_reason()
 *
 * inputs       - reason
 * output       - pointer to static formatted string
 * side effects - none
 */

char *
format_reason(char *reason)
{
  static char reason_result[COMMENT_BUFF];

#ifdef CALVIN
  (void)snprintf(reason_result,sizeof(reason_result) - 1,"%s_%s",reason,
                 date_stamp());
#else
  if(config_entries.hybrid)
    {
      (void)snprintf(reason_result,sizeof(reason_result) - 1,"%s",reason);
    }
  else
    {
      (void)snprintf(reason_result,sizeof(reason_result) - 1,"%s %s",reason,
                     date_stamp());
    }
#endif

  return(reason_result);
}

/*
 * print_motd()
 *
 * inputs       - socket
 * output       - none
 * side effects - prints a message of the day to the connecting client
 *
 * Larz asked for this one. a message of the day on connect
 * I just stole the code from print_help
 */

void 
print_motd(int sock)
{
  FILE *userfile;
  char line[MAX_BUFF];

  if((userfile = fopen(MOTD_FILE,"r")) == NULL)
    {
      print_to_socket(sock,"No MOTD\n");
      return;
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      print_to_socket(sock, "%s", line);
    }
  fclose(userfile);
}

/*
 * list_nicks()
 *
 * inputs       - socket to reply on, nicks to search for,regexpression?
 * output       - NONE
 * side effects -
 */

void 
list_nicks(int sock,char *nick,int regex)
{
  struct hashrec *userptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  int i=0;
  int numfound=0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i=regcomp((regex_t *)&reg, nick, 1)))
  {
    char errbuf[1024];
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    print_to_socket(sock, "Error compiling regular expression: %s\n", errbuf);
    return;
  }
#endif

  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( userptr = domaintable[i]; userptr; userptr = userptr->collision )
        {
#ifdef HAVE_REGEX_H
          if ((regex == YES &&
               !regexec((regex_t *)&reg, userptr->info->nick,1,m,REGEXEC_FLAGS))
              || (regex == NO && !match(nick, userptr->info->nick)))
#else
          if (!match(nick, userptr->info->nick))
#endif
            {
              if(!numfound)
                {
                  print_to_socket(sock,
				  "The following clients match %.150s:\n",nick);
                }
              numfound++;

              print_to_socket(sock,
                   "  %s (%s@%s) {%s}\n",
                   userptr->info->nick,
                   userptr->info->user,userptr->info->host,
                   userptr->info->class);
            }
        }
    }

  if (numfound)
    print_to_socket(sock,
		    "%d matches for %s found\n",numfound,nick);
  else
    print_to_socket(sock,
		    "No matches for %s found\n",nick);
}

/*
 * list_users()
 *
 * inputs       - socket to reply on
 *              - uhost to match on
 *              - regex or no?
 *		- list to save results to
 * output       - NONE
 * side effects -
 */

void 
list_users(int sock,char *userhost,int regex)
{
  struct hashrec *ipptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char uhost[1024];
  int i, numfound = 0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[1024];
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    print_to_socket(sock, "Error compiling regular expression: %s\n",
		    errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      print_to_socket(sock,
"Listing all users is not recommended.  To do it anyway, use '.list ?*@*'.\n");
      return;
    }

  for ( i=0; i < HASHTABLESIZE; ++i)
  {
    for( ipptr = iptable[i]; ipptr; ipptr = ipptr->collision )
    {
      snprintf(uhost, 1024, "%s@%s", ipptr->info->user, ipptr->info->host);
#ifdef HAVE_REGEX_H
      if ((regex == YES &&
          !regexec((regex_t *)&reg, uhost, 1, m, REGEXEC_FLAGS)) 
          || (regex == NO && !match(userhost, uhost)))
#else
      if (!match(userhost, uhost))
#endif 
      {
        if (!numfound++)
          print_to_socket(sock, "The following clients match %s:\n", userhost);

        if (ipptr->info->ip_host[0] > '9' || ipptr->info->ip_host[0] < '0')
          print_to_socket(sock, "  %s (%s@%s) {%s}\n", ipptr->info->nick,
               ipptr->info->user, ipptr->info->host, ipptr->info->class);
        else
          print_to_socket(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
               ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
               ipptr->info->class);
      }
    }
  }
  if (numfound > 0)
    print_to_socket(sock, "%d match%sfor %s found\n", numfound,
		    (numfound > 1 ? "es " : " "), userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
}

/*
 * list_virtual_users()
 *
 * inputs       - socket to reply on
 *              - ipblock to match on
 *              - regex or no?
 * output       - NONE
 * side effects -
 */

void 
list_virtual_users(int sock,char *userhost,int regex)
{
  struct hashrec *ipptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char uhost[1024];
  int i,numfound = 0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE); 
    print_to_socket(sock, "Error compiling regular expression: %s\n",
		    errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      print_to_socket(sock,
"Listing all users is not recommended.  To do it anyway, use '.vlist ?*@*'.\n");
      return;
    }

  for ( i=0; i < HASHTABLESIZE; ++i)
  {
    for( ipptr = iptable[i]; ipptr; ipptr = ipptr->collision )
    {
      snprintf(uhost, 1024, "%s@%s", ipptr->info->user, ipptr->info->ip_host);
#ifdef HAVE_REGEX_H
      if ((regex == YES &&
          !regexec((regex_t *)&reg, uhost, 1, m, REGEXEC_FLAGS))
          || (regex == NO && !match(userhost, uhost)))
#else
      if (!match(userhost, uhost))
#endif 
      {
        if (!numfound++)
          print_to_socket(sock, "The following clients match %s:\n", userhost);

        print_to_socket(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
             ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
             ipptr->info->class);
      }
    }
  }
  if (numfound > 0)
    print_to_socket(sock, "%d match%sfor %s found\n", numfound,
         (numfound > 1 ? "es " : " "), userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
}

void kill_list_users(int sock, char *userhost, char *reason, int regex)
{
  struct hashrec *userptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char fulluh[MAX_HOST+MAX_DOMAIN+2];
  int i, numfound=0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i=regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE);
    print_to_socket(sock, "Error compiling regular expression: %s\n", errbuf);
    return;
  }
#endif

  for (i=0;i<HASHTABLESIZE;++i)
  {
    for (userptr = domaintable[i]; userptr; userptr = userptr->collision)
    {
      snprintf(fulluh, sizeof(fulluh), "%s@%s", userptr->info->user,
               userptr->info->host);
#ifdef HAVE_REGEX_H
      if ((regex == YES &&
           !regexec((regex_t *)&reg, fulluh, 1, m, REGEXEC_FLAGS))
          || (regex == NO && !match(userhost, fulluh)))
#else
      if (!match(userhost, fulluh))
#endif
      {
        if (!numfound++)
          log("killlisted %s\n", fulluh);
        print_to_server("KILL %s :%s", userptr->info->nick, reason);
      }
    }
  }
  if (numfound > 0)
    print_to_socket(sock, "%d matches for %s found\n", userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
}

/*
 * report_multi_host()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */
void report_multi_host(int sock,int nclones)
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
                      print_to_socket(sock,
                           "Multiple clients from the following userhosts:\n");
                    }
      
                  print_to_socket(sock,
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
    print_to_socket(sock, "No multiple logins found.\n");
}

/*
 * report_multi()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
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
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      print_to_socket(sock,
                           "Multiple clients from the following userhosts:\n");
                    }
                  notip = strncmp(userptr->info->domain,userptr->info->host,
                                  strlen(userptr->info->domain)) ||
                    (strlen(userptr->info->domain) ==
                     strlen(userptr->info->host));
                  numfound++;   /* - zaph and next line*/
                  print_to_socket(sock,
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
    print_to_socket(sock, "No multiple logins found.\n");
}

/*
 * report_multi_user()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

void report_multi_user(int sock,int nclones)
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
              if (!match(temp->info->user,userptr->info->user))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;       /* fixed minor boo boo -bill */
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!match(temp->info->user,userptr->info->user))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      print_to_socket(sock,
                           "Multiple clients from the following usernames:\n");
                      foundany = YES;
                    }

                  print_to_socket(sock,
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
      print_to_socket(sock, "No multiple logins found.\n");
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

#ifdef VIRTUAL
void report_multi_virtuals(int sock,int nclones)
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
                      print_to_socket(sock,
                           "Multiple clients from the following ip blocks:\n");
                      foundany = YES;
                    }

                  print_to_socket(sock,
                       " %s %2d connections -- %s.*\n",
                       (numfound-nclones > 3) ? "==>" : "   ",
                       numfound,
                       userptr->info->ip_class_c);
                }
            }
        }
    }

  if (!foundany)
    print_to_socket(sock, "No multiple virtual logins found.\n");
}
#endif

/*
 * report_mem()
 * inputs       - socket to report to
 * output       - none
 * side effects - rough memory usage is reported
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

  for( i = 0; i < HASHTABLESIZE; i++ )
    {
      for( current = hosttable[i]; current; current = current->collision )
        {
          total_hosttable += sizeof(struct hashrec);
          count_hosttable++;

          total_userentry += sizeof(struct userentry);
          count_userentry++;
        }
    }

  for( i = 0; i < HASHTABLESIZE; i++ )
    {
      for( current = domaintable[i]; current; current = current->collision )
        {
          total_domaintable += sizeof(struct hashrec);
          count_domaintable++;
        }
    }

#ifdef VIRTUAL
  for( i = 0; i < HASHTABLESIZE; i++ )
    {
      for( current = iptable[i]; current; current = current->collision )
        {
          total_iptable += sizeof(struct hashrec);
          count_iptable++;
        }
    }
#endif

  for( i = 0; i < HASHTABLESIZE; i++ )
    {
      for( current = usertable[i]; current; current = current->collision )
        {
          total_usertable += sizeof(struct hashrec);
          count_usertable++;
        }
    }

  print_to_socket(sock,"Total hosttable memory %lu/%d entries\n",
       total_hosttable,count_hosttable);

  print_to_socket(sock,"Total usertable memory %lu/%d entries\n",
       total_usertable,count_usertable);

  print_to_socket(sock,"Total domaintable memory %lu/%d entries\n",
       total_domaintable,count_domaintable);

  print_to_socket(sock,"Total iptable memory %lu/%d entries\n",
       total_iptable, count_iptable);

  print_to_socket(sock,"Total user entry memory %lu/%d entries\n",
       total_userentry, count_userentry);

  print_to_socket(sock,"Total memory in use %lu\n",
       total_hosttable + total_domaintable + total_iptable + total_userentry);

  print_to_socket(sock,"Total memory allocated over time: %lu\n", totalmem);
}

/*
 * report_clones
 *
 * inputs       - socket to report on
 * output       - NONE
 * side effects - NONE
 */

void 
report_clones(int sock)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int  numfound;
  int i;
  int j=0;
  int k;
  int foundany = NO;
  time_t connfromhost[MAXFROMHOST];

  if(sock < 0)
    return;

  for ( i = 0; i < HASHTABLESIZE; ++i)
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
                            print_to_socket(sock,
                                 "Possible clonebots from the following hosts:\n");
                          foundany = YES;
                        }
                        print_to_socket(sock,
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
        print_to_socket(sock, "No potential clonebots found.\n");
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
 * list_class()
 *
 * inputs       - integer socket to reply on
 *              - integer class to search for
 *              - integer show total only YES/NO
 * output       - NONE
 * side effects -
 */

void 
list_class(int sock,char *class_to_find,int total_only)
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
                      print_to_socket(sock,
                           "The following clients are in class %s\n",
                           class_to_find);
                    }
                }
              if(!total_only)
                {
                  print_to_socket(sock,
                       "  %s (%s@%s)\n",
                       userptr->info->nick,
                       userptr->info->user,userptr->info->host);
                }
            }
        }
    }

  if (num_found)
    print_to_socket(sock,
         "%d are in class %s\n", num_found, class_to_find );
  else
    print_to_socket(sock,
         "Nothing found in class %s\n", class_to_find );
  print_to_socket(sock,"%d unknown class\n", num_unknown);
}

#ifdef VIRTUAL
void
report_vbots(int sock,int nclones)
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
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      print_to_socket(sock,
                           "Multiple clients from the following userhosts:\n");
                    }
                  numfound++;   /* - zaph and next line*/
                  print_to_socket(sock,
                       " %s %2d connections -- %s@%s.* {%s}\n",
                       (numfound-nclones > 2) ? "==>" :
                       "   ",numfound,userptr->info->user,
                       userptr->info->ip_class_c,
                       userptr->info->class);
                }
            }
        }
    }
  if (!foundany)
    print_to_socket(sock, "No multiple logins found.\n");
}
#endif

/*
 * report_domains
 * input        - sock
 *              - num
 * output       - NONE
 * side effects -
 */

struct sortarray sort[MAXDOMAINS+1];

void 
report_domains(int sock,int num)
{
  struct hashrec *userptr;

  int inuse = 0;
  int i;
  int j;
  int maxx;
  int found;
  int foundany = NO;

  for ( i = 0; i < HASHTABLESIZE; i++ )
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
  FOREVER
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
          print_to_socket(sock,"Domains with most users on the server:\n");
        }

      print_to_socket(sock,"  %-40s %3d users\n",
           sort[found].domainrec->domain,maxx);
      sort[found].count = 0;
    }

  if (!foundany)
    {
      print_to_socket(sock, "No domains have %d or more users.\n",num);
    }
  else
    {
      print_to_socket(sock, "%d domains found\n", inuse);
    }
}

/*
 * do_a_kline()
 *
 * inputs       - command used i.e. ".kline", ".kclone" etc.
 *              - kline_time if non-zero its HYBRID and its a tkline
 *              - pattern (i.e. nick or user@host)
 *              - reason
 *              - who asked for this (oper)
 * output       - NONE
 * side effects - someone gets k-lined
 *
 *
 */

void
do_a_kline(char *command_name,int kline_time, char *pattern,
	   char *reason,char *who_did_command)
{
  if(pattern == NULL)
    return;

  if(reason == NULL)
    return;

  /* Removed *@ prefix from kline parameter -tlj */

  if(config_entries.hybrid)
    {
      if(kline_time)
        send_to_all(SEND_ALL,
                     "%s %d %s : %s added by oper %s",
                     command_name,
                     kline_time,
                     pattern,
                     format_reason(reason),
                     who_did_command);
      else
        send_to_all(SEND_ALL,
                     "%s %s : %s added by oper %s",
                     command_name,
                     pattern,
                     format_reason(reason),
                     who_did_command);
    }
  else
    {
      send_to_all(SEND_ALL,
                   "%s %s : %s added by oper %s",
                   command_name,
                   pattern,
                   format_reason(reason),
                   who_did_command);
    }
  /* If the kline doesn't come from the local tcm
   * and tcm has been compiled to restrict remote klines
   * then just ignore it
   */

  log_kline("KLINE",
            pattern,
            kline_time,
            who_did_command,
            reason);

  if(config_entries.hybrid)
    {
#ifdef HIDE_OPER_IN_KLINES
      if(kline_time)
        print_to_server("KLINE %d %s :%s",
               kline_time,pattern,
               reason);
      else
        print_to_server("KLINE %s :%s",
               pattern,
               reason);
#else
      if(kline_time)
        print_to_server("KLINE %d %s :%s [%s]",
               kline_time,pattern,reason,
               who_did_command);
      else
        print_to_server("KLINE %s :%s [%s]",
               pattern,reason,
               who_did_command);
#endif
    }
  else
    {
#ifdef HIDE_OPER_IN_KLINES
      print_to_server("KLINE %s :%s",
             pattern,
             format_reason(reason));
#else
      print_to_server("KLINE %s :%s [%s]",
             pattern,format_reason(reason),
             who_did_command);
#endif
    }
}

/*
 * initopers()
 *
 * inputs       - NONE
 * output       - NONE
 * side effects - start determining who by default has dcc privileges
 *                by checking the stats O list of the server.
 *
 */

void
initopers(void)
{
  clear_userlist();
  load_userlist();
  print_to_server("STATS O");
}

void
inithash()
{
  freehash();
  doingtrace = YES;
  print_to_server("TRACE");
}

void
report_failures(int sock,int num)
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
          print_to_socket(sock, "Userhosts with most connect rejections:\n");
          print_to_socket(sock," %5d rejections: %s@%s%s\n", found->failcount,
               (*found->user ? found->user : "<UNKNOWN>"), found->host,
               (found->botcount ? " <BOT>" : ""));
        }
      found->failcount = -found->failcount;   /* Yes, this is horrible */
    }

  if (!foundany)
    {
      print_to_socket(sock,"No userhosts have %d or more rejections.\n",num);
    }

  for( tmp = failures; tmp; tmp = tmp->next )
    {
      if (tmp->failcount < 0)
        tmp->failcount = -tmp->failcount;   /* Ugly, but it works. */
    }
}

