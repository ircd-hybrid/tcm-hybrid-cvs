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

/* $Id: stdcmds.c,v 1.77 2002/05/27 21:02:35 db Exp $ */

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
#include "hash.h" /* XXX */
#include "bothunt.h" /* XXX */
#include "stdcmds.h"
#include "userlist.h"
#include "wild.h"

int doingtrace = NO;

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
      privmsg(config_entries.defchannel, "%s", msg);
    }

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

