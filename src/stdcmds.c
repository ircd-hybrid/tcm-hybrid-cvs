/************************************************************
* MrsBot by Hendrix <jimi@texas.net>                        *
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

/* $Id: stdcmds.c,v 1.44 2002/04/17 22:09:27 wcampbel Exp $ */

#include "setup.h"

#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "tcm.h"
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

#ifdef DMALLOC
#include "dmalloc.h"
#endif

int doingtrace = NO;

extern struct connection connections[];
extern int get_action_type(char *name);

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

/*
 * toserv
 *
 * inputs       - msg to send directly to server
 * output       - NONE
 * side effects - server executes command.
 */

void 
toserv(char *format, ... )
{
  char msgbuf[MAX_BUFF];
  va_list va;

  va_start(va,format);

  if (connections[0].socket != INVALID)
    {
      vsnprintf(msgbuf,sizeof(msgbuf),format, va);
      send(connections[0].socket, msgbuf, strlen(msgbuf), 0);
    }
#ifdef DEBUGMODE
  printf("->%s", msgbuf);
#endif

  va_end(va);
}

/*
 * prnt()
 *
 * inputs        - socket to reply on
 * output        - NONE
 * side effects  - NONE
 */
void
prnt(int sock, char *format, ...)
{
  char msgbuf[MAX_BUFF];
  va_list va;

  va_start(va,format);

  vsnprintf(msgbuf, sizeof(msgbuf)-2, format, va);
  if (msgbuf[strlen(msgbuf)-1] != '\n') strncat(msgbuf, "\n\0", 2);
  send(sock, msgbuf, strlen(msgbuf), 0);

  if(config_entries.debug)
    {
      (void)printf("-> %s",msgbuf);     /* - zaph */
      if(outfile)
        (void)fprintf(outfile,"%s",msgbuf);
    }
 va_end(va);
}


/* The following are primitives that send messages to the server to perform
 * certain things.  The names are quite self explanatory, so I am not going
 * to document each.  By no means are they complex.
 */

void
oper()
{
  toserv("OPER %s %s\n",
          config_entries.oper_nick_config,
          config_entries.oper_pass_config);
}

void
op(char *chan,char *nick)
{
  toserv("MODE %s +o %s\n", chan, nick);
}

void
join(char *chan, char *key)
{
  if (key != NULL)
    toserv("JOIN %s %s\n", chan, key);
  else
    toserv("JOIN %s\n", chan);
}

void
leave(char *chan)
{
  toserv("PART %s\n", chan);
}

void
notice(char *nick,...)
{
  va_list va;
  char msg[MAX_BUFF];
  char *format;

  va_start(va,nick);

  format = va_arg(va, char*);
  vsprintf(msg, format, va );

  toserv("NOTICE %s :%s\n", nick, msg);
  va_end(va);
}

void
privmsg(char *nick,...)
{
  va_list va;
  char msg[MAX_BUFF];
  char *format;

  va_start(va,nick);

  format = va_arg(va, char*);
  vsprintf(msg, format, va );
  toserv("PRIVMSG %s :%s", nick, msg);

  va_end(va);
}

void
newnick(char *nick)
{
  toserv("NICK %s\n", nick);
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
  sendtoalldcc(type,"%s",msg);

  if( channel_send_flag & config_entries.channel_report )
    {
      msg_mychannel("%s", msg);
    }

  va_end(va);
}

/*
 * char *suggest_host(char *host, int type)
 *
 * inputs       - raw hostname
 *		- ident?
 *              - type of kline
 * output       - hostname stripped to klinable form
 * side effects - NONE
*/
static char *
suggest_host(char *host, int ident, int type)
{
  static char work_host[MAX_HOST];
  char *p = work_host;
  char *q = work_host;
  int dots = 0;
  int ip_number = YES;

  strncpy(work_host, host, MAX_HOST-1);

  while (*p)
    {
      if (*p == '.')
        ++dots;
      else if (!isdigit(*p))
        ip_number = NO;
      ++p;
    }

  if (dots != 3)
    ip_number = NO;

  if (type & get_action_type("cflood"))
    return q;
  if (type & get_action_type("link"))
    return q;
  if (type & get_action_type("clone"))
    return q;
  if (type & get_action_type("sclone"))
    return q;
  if (type & get_action_type("drone"))
    return q;
  if (type & get_action_type("wingate"))
    return q;
  if (type & get_action_type("socks"))
    return q;
  if (type & get_action_type("vclone"))
    {
      if (ip_number)  /* note: if a vclone is passing a non-ip host to us, something's wrong */
        {
           while (*p != '.')
            if ((--p) == q)                 /* JUST in case */
              break;

          *(p++) = '.';
          *(p++) = '*';
          *p = '\0';

          return q;
        }
      /* if we are still here,
       * hopefully the older part of suggset_host() will catch it
       */
    }
  if (type & get_action_type("flood"))
    {
      if (!ident)
        return q;
    }
  if (type & get_action_type("bot"))
    {
      if (!ident)
        return q;
    }
  if (type & get_action_type("spambot"))
    {
      if (!ident)
        return q;
    }

  if (ip_number && !(type & get_action_type("clone")))
    {
      while (*p != '.')
        if ((--p) == q)                 /* JUST in case */
          break;

      *(p++) = '.';
      *(p++) = '*';
      *p = '\0';

      return q;
    }
  else if (ip_number)
    return q;

  if (dots > 1)
    {
      while (*q != '.')
        if (*(++q) == '\0')                     /* JUST in case */
          break;

      p = q;
      while (*p) ++p;
      while (*p != '.') --p;
      p++;

/* I am now at the end of the hostname. the last little bit is the top
 * level domain. if its only two letters, then its a country domain, and I
 * have to rescan
 */
      if (strlen(p) != 3)
        {                       /* sigh try again */
          q = work_host;
          if (dots > 2)
            {
              while (*q != '.')
                if (*(++q) == '\0')             /* JUST in case */
                  break;
              *(--q) = '*';
            }
        }
      else
        *(--q) = '*';
    }

  return q;
}

/*
 * suggest_action
 *
 *  Suggest an action for the tcm to use
 * inputs       - reason, integer corresponding to type which kline is needed
 *              - nick
 *              - user name
 *              - host name
 *              - identd, its identd'ed or not
 * output       - none
 * side effects - connected opers are dcc'ed a suggested kline or kill
 *
 * I have to reassemble user and host back into a u@h, in order
 * to do matching of users not to KILL or KLINE. urgh. This seems
 * silly as I have had to split them elsewhere.
 *
 *      - Dianora
 *              Changes by bill, 6/2000.
 *
 * revamped and renamed suggest_action during 3.0.1 overhaul 9/2001
 *  -bill
 */

void
suggest_action(int type_s,
	       char *nick,
	       char *user,
	       char *host,
	       int different,
	       int identd)
{
  char suggested_user[MAX_USER+1];
  char action[15], reason[MAX_BUFF];
  char *suggested_host=NULL;
  int i, type;

  if (type_s < 0)
    type = -type_s;
  else
    type = type_s;

  suggested_user[0] = '\0';

  if (user != NULL && host != NULL)
    {
      /* Don't kill or kline exempted users */
      if(okhost(user, host, type))
        return;

      if (strchr(host,'*') != (char *)NULL)
        return;

      if (strchr(host,'?') != (char *)NULL)
        return;

      if (identd && !different)
        strcpy(suggested_user,user);
      else 
        strcpy(suggested_user, "*");

      if (type & get_action_type("clone"))
        {
          strcpy(suggested_user, "*");
        }
      else if (type & get_action_type("sclone"))
        {
          strcpy(suggested_user, "*");
        }
      else if (type & get_action_type("drone"))
        {
          strcpy(suggested_user, "*");
        }
      else if (type & get_action_type("wingate"))
        {
          strcpy(suggested_user, "*");
        }
      else if (type & get_action_type("socks"))
        {
          strcpy(suggested_user, "*");
        }

      suggested_host=suggest_host(host, identd, type);
    }
  else if (user == NULL && host != NULL)
    {
      sprintf(suggested_user, "*");
      suggested_host=suggest_host(host, identd, type);
    }

  if (suggested_user[0] && suggested_host &&
      okhost(suggested_user, suggested_host, type))
    return;

  for (i = 0; i < MAX_ACTIONS; i++)
    if (type == actions[i].type) break;

  if (type != actions[i].type) return; /* how did we not find it? */

  snprintf(action, sizeof(action), "%s", actions[i].method);
  snprintf(reason, sizeof(reason), "%s", actions[i].reason);

  if (strcasecmp(action, "warn") == 0 && type_s > 0)
    return;
  else if (strcasecmp(action, "warn") == 0 && type_s < 0)
  {
    if (suggested_user[0] == '\0' || suggested_host == NULL)
      {
        if (different)
          toserv("KLINE %d %s :%s\n", different, nick, reason);
        else
          toserv("KLINE %s :%s\n", nick, reason);
        return;
      }

    if (different)
      toserv("KLINE %d %s@%s :%s\n", different, suggested_user,
             suggested_host, reason);
    else
      toserv("KLINE %s@%s :%s\n", suggested_user, suggested_host, reason);
  }

  if (suggested_user[0] == '\0' || suggested_host == NULL)
    {
      toserv("%s %s :%s\n", action, nick, reason);
      return;
    }

  if (strncasecmp(action, "dline", 5) == 0)
    toserv("%s %s :%s\n", action, host, reason);
  else
    toserv("%s %s@%s :%s\n", action, suggested_user, suggested_host, reason);


  /* 
   * so as to avoid all confusion, it is now the responsibility of the calling
   * function to inform the DCC users of the infraction.
   */
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
  char *errbuf=NULL;
  regex_t reg;
  regmatch_t m[1];
#endif
  int i=0;
  int numfound=0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i=regcomp((regex_t *)&reg, nick, 1)))
  {
    if ((errbuf = (char *)malloc(1024)) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_nicks()");
      exit(0);
    }
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    prnt(sock, "Error compiling regular expression: %s\n", errbuf);
    free(errbuf);
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
#ifdef HAVE_REGEX_H
  if (errbuf != NULL)
    free(errbuf);
#endif
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
  char *errbuf=NULL;
  regex_t reg;
  regmatch_t m[1];
#endif
  char *uhost, *uhostmatch;
  int i, numfound = 0;
  if ((uhost = (char *)malloc(1024)) == NULL)
  {
    sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_users()\n");
    exit(0);
  }
  if ((uhostmatch = (char *)malloc(1024)) == NULL)
  {
    sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_users()\n");
    exit(0);
  }
  if (strchr(userhost, '@') == NULL && regex != YES)
    snprintf(uhostmatch, 1024, "*@%s", userhost);
  else
    snprintf(uhostmatch, 1024, "%s", userhost);

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    if ((errbuf = (char *)malloc(1024)) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_users()\n");
      exit(0);
    }
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    prnt(sock, "Error compiling regular expression: %s\n", errbuf);
    free(errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      prnt(sock, "Listing all users is not recommended.  To do it anyway, use '.list ?*@*'.\n");
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
          || (regex == NO && !match(uhostmatch, uhost)))
#else
      if (!match(uhostmatch, uhost))
#endif 
      {
        if (!numfound++)
          prnt(sock, "The following clients match %s:\n", uhostmatch);

        if (ipptr->info->ip_host[0] > '9' || ipptr->info->ip_host[0] < '0')
          prnt(sock, "  %s (%s@%s) {%s}\n", ipptr->info->nick,
               ipptr->info->user, ipptr->info->host, ipptr->info->class);
        else
          prnt(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
               ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
               ipptr->info->class);
      }
    }
  }
  if (numfound > 0)
    prnt(sock, "%d matche%sfor %s found\n", numfound,
         (numfound > 1 ? "s " : " "), uhostmatch);
  else
    prnt(sock, "No matches for %s found\n", uhostmatch);
  free(uhost);
  free(uhostmatch);
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
  char *errbuf;
  regex_t reg;
  regmatch_t m[1];
#endif
  char *uhost, *uhostmatch;
  int i,numfound = 0;

  if ((uhost = (char *)malloc(1024)) == NULL)
  {
    sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_users()\n");
    exit(0);
  }
  if ((uhostmatch = (char *)malloc(1024)) == NULL)
  {
    sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_users()\n");
    exit(0);
  }
  if (strchr(userhost, '@') == NULL && regex != YES)
    snprintf(uhostmatch, 1024, "*@%s", userhost);
  else
    snprintf(uhostmatch, 1024, "%s", userhost);

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    if ((errbuf = (char *)malloc(1024)) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in list_users()\n");
      exit(0);
    }
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    prnt(sock, "Error compiling regular expression: %s\n", errbuf);
    free(errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      prnt(sock, "Listing all users is not recommended.  To do it anyway, use '.vlist ?*@*'.\n");
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
          || (regex == NO && !match(uhostmatch, uhost)))
#else
      if (!match(uhostmatch, uhost))
#endif 
      {
        if (!numfound++)
          prnt(sock, "The following clients match %s:\n", uhostmatch);

        prnt(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
             ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
             ipptr->info->class);
      }
    }
  }
  if (numfound > 0)
    prnt(sock, "%d matche%sfor %s found\n", numfound,
         (numfound > 1 ? "s " : " "), uhostmatch);
  else
    prnt(sock, "No matches for %s found\n", uhostmatch);
  free(uhost);
  free(uhostmatch);
}

void kill_list_users(int sock, char *userhost, char *reason, int regex)
{
  struct hashrec *userptr;
#ifdef HAVE_REGEX_H
  char *errbuf=NULL;
  regex_t reg;
  regmatch_t m[1];
#endif
  char fulluh[MAX_HOST+MAX_DOMAIN+2];
  int i, numfound=0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i=regcomp((regex_t *)&reg, userhost, 1)))
  {
    if ((errbuf = (char *)malloc(1024)) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in kill_list_users()\n");
      exit(0);
    }
    regerror(i, (regex_t *)&reg, errbuf, 1024);
    prnt(sock, "Error compiling regular expression: %s\n", errbuf);
    free(errbuf);
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
        toserv("KILL %s :%s\n", userptr->info->nick, reason);
      }
    }
  }
  if (numfound > 0)
    prnt(sock, "%d matches for %s found\n", userhost);
  else
    prnt(sock, "No matches for %s found\n", userhost);
#ifdef HAVE_REGEX_H
  if (errbuf != NULL)
    free(errbuf);
#endif
}
/*
 * report_multi_host()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

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
  int j;
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
                      prnt(sock,
                           "Multiple clients from the following userhosts:\n");
                    }
                  numfound++;   /* - zaph and next line*/
                  prnt(sock,
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
    prnt(sock, "No multiple logins found.\n");
}

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
        sendtoalldcc(SEND_OPERS_ONLY,
                     "%s %d %s : %s added by oper %s\n",
                     command_name,
                     kline_time,
                     pattern,
                     format_reason(reason),
                     who_did_command);
      else
        sendtoalldcc(SEND_OPERS_ONLY,
                     "%s %s : %s added by oper %s\n",
                     command_name,
                     pattern,
                     format_reason(reason),
                     who_did_command);
    }
  else
    {
      sendtoalldcc(SEND_OPERS_ONLY,
                   "%s %s : %s added by oper %s\n",
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
        toserv("KLINE %d %s :%s\n",
               kline_time,pattern,
               reason);
      else
        toserv("KLINE %s :%s\n",
               pattern,
               reason);
#else
      if(kline_time)
        toserv("KLINE %d %s :%s [%s]\n",
               kline_time,pattern,reason,
               who_did_command);
      else
        toserv("KLINE %s :%s [%s]\n",
               pattern,reason,
               who_did_command);
#endif
    }
  else
    {
#ifdef HIDE_OPER_IN_KLINES
      toserv("KLINE %s :%s\n",
             pattern,
             format_reason(reason));
#else
      toserv("KLINE %s :%s [%s]\n",
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
  toserv("STATS O\n");
}

void
inithash()
{
  freehash();
  doingtrace = YES;
  toserv("TRACE\n");
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

