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

/* $Id: stdcmds.c,v 1.100 2002/11/27 02:41:13 bill Exp $ */

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
#include "parse.h"
#include "logging.h"
#include "stdcmds.h"
#include "userlist.h"
#include "wild.h"
#include "hash.h"

/* The following are primitives that send messages to the server to perform
 * certain things.  The names are quite self explanatory, so I am not going
 * to document each.  By no means are they complex.
 */

void
oper()
{
  send_to_server("OPER %s %s",
          config_entries.oper_nick_config,
          config_entries.oper_pass_config);
}

void
op(char *chan,char *nick)
{
  send_to_server("MODE %s +o %s", chan, nick);
}

void
join(void)
{
  if((config_entries.channel == NULL) || 
     (*config_entries.channel == '\0'))
    return;

  send_to_server("JOIN %s %s", 
 	          config_entries.channel, config_entries.channel_key);
}

void
leave(char *chan)
{
  send_to_server("PART %s", chan);
}


void
newnick(char *nick)
{
  send_to_server("NICK %s", nick);
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
report(int type, char *format,...)
{
  char msg[MAX_BUFF];
  va_list va;

  va_start(va,format);
  vsnprintf(msg, sizeof(msg)-2,format,va);

  /* Probably not a format string bug, but I'm calling it this way
  ** for safety sake - Hwy
  */
  send_to_all(NULL, type, "%s", msg);

  if(config_entries.channel != '\0')
    privmsg(config_entries.channel, "%s", msg);

  va_end(va);
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
 * inputs       - pointer to struct connection
 * output       - none
 * side effects - prints a message of the day to the connecting client
 *
 * Larz asked for this one. a message of the day on connect
 * I just stole the code from print_help
 */

void 
print_motd(struct connection *connection_p)
{
  FILE *userfile;
  char line[MAX_BUFF];

  if((userfile = fopen(MOTD_FILE,"r")) == NULL)
    {
      send_to_connection(connection_p, "No MOTD");
      return;
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      send_to_connection(connection_p, "%s", line);
    }
  fclose(userfile);
}



/*
 * do_a_kline()
 *
 * inputs       - kline_time if non-zero its HYBRID and its a tkline
 *              - pattern (i.e. nick or user@host)
 *              - reason
 *              - who asked for this (oper)
 * output       - NONE
 * side effects - someone gets k-lined
 */

void
do_a_kline(int kline_time, char *pattern,
	   char *reason, struct connection *connection_p)
{
  if(pattern == NULL)
  {
    send_to_connection(connection_p, "KLINE failed.  No user@host.");
    return;
  }

  if(reason == NULL)
  {
    send_to_connection(connection_p, "KLINE failed.  No reason.");
    return;
  }

  log_kline("KLINE", pattern, kline_time, connection_p->registered_nick, reason);

  if(config_entries.hybrid)
    {
#ifdef HIDE_OPER_IN_KLINES
      if(kline_time)
        send_to_server("KLINE %d %s :%s", kline_time, pattern, reason);
      else
        send_to_server("KLINE %s :%s", pattern, reason);
#else
      if (connection_p->type & FLAGS_INVS)
      {
        if (kline_time)
          send_to_server("KLINE %d %s :%s", kline_time, pattern, reason);
        else
          send_to_server("KLINE %s :%s", pattern, reason);
      }
      else
      {
        if (kline_time)
          send_to_server("KLINE %d %s :%s [%s]", kline_time, pattern, reason, connection_p->registered_nick);
        else
          send_to_server("KLINE %s :%s [%s]", pattern, reason, connection_p->registered_nick);
      }
#endif
    }
  else
    {
#ifdef HIDE_OPER_IN_KLINES
      send_to_server("KLINE %s :%s", pattern, format_reason(reason));
#else
      if (connection_p->type & FLAGS_INVS)
        send_to_server("KLINE %s :%s", pattern, format_reason(reason));
      else
        send_to_server("KLINE %s :%s [%s]", pattern, format_reason(reason), connection_p->registered_nick);
#endif
    }
}

void
report_failures(struct connection *connection_p, int num)
{
  int maxx;
  int foundany = NO;
  struct failrec *ptr;
  struct failrec *found;

  /* Print 'em out from highest to lowest */
  FOREVER
    {
      maxx = num-1;
      found = NULL;

      for (ptr = failures; ptr; ptr = ptr->next)
        {
          if(ptr->failcount > maxx)
            {
              found = ptr;
              maxx = ptr->failcount;
            }
        }

      if(!found)
        break;

      if(foundany == 0)
        {
	  foundany++;
          send_to_connection(connection_p,
			     "Userhosts with most connect rejections:");
          send_to_connection(connection_p, " %5d rejections: %s@%s",
			     found->failcount,
			     (*found->username ? found->username : "<UNKNOWN>"),
			     found->host);
        }
      found->failcount = -found->failcount;   /* Yes, this is horrible */
    }

  if(foundany == 0)
    {
      send_to_connection(connection_p,
			 "No userhosts have %d or more rejections.",num);
    }

  /* XXX what is this "Ugly, but it works" ? */

  for (ptr = failures; ptr; ptr = ptr->next)
    {
      if(ptr->failcount < 0)
        ptr->failcount = -ptr->failcount;   /* Ugly, but it works. */
    }
}

