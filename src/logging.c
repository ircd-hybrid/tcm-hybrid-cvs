/*
 * logging.c
 * All the logging type functions moved to here for tcm
 *
 * $Id: logging.c,v 1.39 2002/05/28 00:35:10 db Exp $
 *
 * - db
 */

#include "setup.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif


#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "config.h"
#include "tcm.h"
#include "userlist.h"
#include "tcm_io.h"
#include "bothunt.h"
#include "parse.h"
#include "logging.h"
#include "stdcmds.h"

FILE *outfile;             /* Debug output file handle
			    * Now shared with writing pid file
			    */


static FILE *initlog(void);
static void timestamp_log(FILE *);
static char *duration(double);

/*
 *   Chop a string of form "nick [user@host]" or "nick[user@host]" into
 *   nick and userhost parts.  Return pointer to userhost part.  Nick
 *   is still pointed to by the original param.  Note that since [ is a
 *   valid char for both nicks and usernames, this is non-trivial.
 */

void 
chopuh(int istrace,char *nickuserhost,struct plus_c_info *userinfo)
{
  char *uh;
  char *p;
  char skip = NO;
  char *right_brace_pointer;
  char *right_square_bracket_pointer;
/* I try to pick up an [IP] from a connect or disconnect message
 * since this routine is also used on trace, some heuristics are
 * used to determine whether the [IP] is present or not.
 * *sigh* I suppose the traceflag could be used to not even go
 * through these tests
 * bah. I added a flag -Dianora
 */

  userinfo->user = NULL;
  userinfo->host = NULL;
  memset(userinfo->ip,0,sizeof(userinfo->ip));

  /* ok, if its a hybrid server or modified server,
   * I go from right to left picking up extra bits
   * [ip] {class}, then go and pick up the nick!user@host bit
   */

  if(!istrace)  /* trace output is not the same as +c output */
    {
      snprintf(userinfo->class, sizeof(userinfo->class) - 1, "unknown");

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
          snprintf(userinfo->ip, sizeof(userinfo->ip), "%s", p);
      }
    }

  /* If it's the first format, we have no problems */
  if ( !(uh = strchr(nickuserhost,' ')) )
    {
      if( !(uh = strchr(nickuserhost,'[')) )
        {
          if( !(uh = strchr(nickuserhost,'(')) )        /* lets see... */
            {                                   /* MESSED up GIVE UP */
              (void)fprintf(stderr,
                            "You have VERY badly screwed up +c output!\n");
              (void)fprintf(stderr,
                            "1st case nickuserhost = [%s]\n", nickuserhost);
              return;           /*screwy...prolly core in the caller*/
            }

          if((p = strrchr(uh,')')))
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
          userinfo->user = uh+1;
          if((p = strchr(userinfo->user,'@')))
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
}

/*
 * initlog()
 *
 * inputs - NONE
 * output - FILE pointer to the log file
 * side effects
 *
 */

static FILE 
*initlog(void)
{
  time_t current_time;
  struct tm *broken_up_time;
  char filename[MAX_BUFF];
  char last_filename[MAX_BUFF];
  char *p;
  FILE *last_log_fp;
  FILE *l_fp;
#ifdef HOW_TO_MAIL
  FILE *email_fp;
  FILE *log_to_email_fp;
  char command[MAX_BUFF];
#endif

#ifdef LOGFILE
  last_filename[0] = '\0';

  if ((last_log_fp = fopen(LAST_LOG_NAME,"r")) != NULL)
    {
      (void)fgets(last_filename,MAX_BUFF-1,last_log_fp);
      if ((p = strchr(last_filename,'\n')) != NULL)
	*p = '\0';

      if(config_entries.debug && (outfile != NULL))
	{
	  (void)fprintf(outfile, "last_filename = [%s]\n", last_filename );
	}
      (void)fclose(last_log_fp);
    }

  current_time = time((time_t *)NULL);
  broken_up_time = localtime(&current_time);

  (void)snprintf(filename,sizeof(filename) - 1,"%s_%02d_%02d_%04d",LOGFILE,
		(broken_up_time->tm_mon)+1,broken_up_time->tm_mday,
		broken_up_time->tm_year + 1900);

  if ((l_fp = fopen(filename,"a")) == NULL)
    return (NULL);

  if( !last_filename[0] )
    {
      strcpy(last_filename,filename);
    }

  if(!config_entries.email_config[0])
    return (l_fp);

#ifdef HOW_TO_MAIL
  if( (strcmp(last_filename,filename)) != 0 )
    {
      (void)snprintf(command,sizeof(command) - 1,"%s \"clone report\" %s",
                     HOW_TO_MAIL, config_entries.email_config);
      if( (email_fp = popen(command,"w")) )
	{
	  if ((log_to_email_fp = fopen(last_filename,"r")) != NULL)
	    {
	      while(fgets(command,MAX_BUFF-1,log_to_email_fp ) != NULL)
		(void)fputs(command,email_fp);
	      (void)fclose(log_to_email_fp);
	    }
	  (void)fclose(email_fp);
	}
      (void)unlink(last_filename);
    }
#endif
  if ((last_log_fp = fopen(LAST_LOG_NAME,"w")) != NULL)
    {
      (void)fputs(filename,last_log_fp);
      (void)fclose(last_log_fp);
    }
#endif

  return l_fp;
}

/*
 * timestamp_log()
 *
 * inputs - NONE
 * output - NONE
 * side effects
 *
 */

void 
timestamp_log(FILE *fp)
{
  struct tm *broken_up_time;

  if(fp == NULL)
    return;

  broken_up_time = localtime(&current_time);

  (void)fprintf(fp,"%02d/%02d/%04d %02d:%02d\n",
		(broken_up_time->tm_mon)+1,
		broken_up_time->tm_mday,
		broken_up_time->tm_year+1900,
		broken_up_time->tm_hour,
		broken_up_time->tm_min);
}

/*
 * log_kline
 *
 * input	- command_name "KLINE" "GLINE" etc.
 *		- who_did_command who did the command
 *		- int time if its a temporary kline
 *		- reason
 * output	- none
 * side effects	- log entry made
 */

void 
log_kline(char *command_name,
	       char *pattern,
	       int  kline_time,
	       char *who_did_command,
	       char *reason)
{
  time_t current_time;
  struct tm *broken_up_time;
  FILE *fp_log;

  current_time = time(NULL);
  broken_up_time = localtime(&current_time);

#ifdef KILL_KLINE_LOG
  if( (fp_log = fopen(KILL_KLINE_LOG,"a")) )
    {
      if(config_entries.hybrid)
	{
	  if(kline_time)
	    fprintf(fp_log,"%02d/%02d/%4d %02d:%02d %s %d %s by %s for %s\n",
		    (broken_up_time->tm_mon)+1,
		    broken_up_time->tm_mday,
		    broken_up_time->tm_year+1900,
		    broken_up_time->tm_hour,
		    broken_up_time->tm_min,
		    command_name,
		    kline_time,
		    pattern,
		    who_did_command,reason);
	  else
	    fprintf(fp_log,"%02d/%02d/%4d %02d:%02d %s %s by %s for %s\n",
		    (broken_up_time->tm_mon)+1,
		    broken_up_time->tm_mday,
		    broken_up_time->tm_year+1900,
		    broken_up_time->tm_hour,
		    broken_up_time->tm_min,
		    command_name,
		    pattern,
		    who_did_command,reason);
	}
      else
	{
	  fprintf(fp_log,"%02d/%02d/%4d %02d:%02d %s %s by %s for %s\n",
		  (broken_up_time->tm_mon)+1,
		  broken_up_time->tm_mday,
		  broken_up_time->tm_year+1900,
		  broken_up_time->tm_hour,
		  broken_up_time->tm_min,
		  command_name,
		  pattern,
		  who_did_command,reason);
	}

      (void)fclose(fp_log);
    }
#endif
}

/*
 * logclear()
 * inputs	- NONE
 * output	- NONE
 * side effects	-
 */

void
logclear(void)
{
  struct failrec *tmp, *hold;

  tmp = hold = NULL;

  while ((tmp = failures) != NULL)
    {
        hold = tmp->next;
        failures = hold;
        xfree(tmp);
    }
}
        

/*
 * logfailure()
 *
 * inputs       - pointer to nick!user@host
 *              - if a bot reject or not
 * output       - NONE
 * side effects -
 */

void 
logfailure(char *nickuh,int botreject)
{
  struct plus_c_info userinfo;
  struct failrec *tmp, *hold = NULL;

  chopuh(YES,nickuh,&userinfo); /* use trace form of chopuh() */

  tmp = failures;
  while (tmp != NULL)
    {
      if(!strcasecmp(tmp->user,userinfo.user)&&!strcasecmp(tmp->host,
                                                           userinfo.host))
        {
          /* For performance, move the most recent to the head of the queue */
          if (hold != NULL)
            {
              hold->next = tmp->next;
              tmp->next = failures;
              failures = tmp;
            }
          break;
        }
      hold = tmp;
      tmp = tmp->next;
    }

  if (tmp == NULL)
    {
      tmp = (struct failrec *)xmalloc(sizeof(struct failrec));

      strncpy(tmp->user,userinfo.user,11);
      tmp->user[10] = '\0';
      strncpy(tmp->host,userinfo.host,MAX_HOST);
      tmp->host[79] = '\0';
      tmp->failcount = tmp->botcount = 0;
      tmp->next = failures;
      failures = tmp;
    }
  if (botreject)
    ++tmp->botcount;
  ++tmp->failcount;
}


/*
 * kline_report
 *
 * inputs	- rest of notice from server
 * output	- NONE
 * side effects	- Reports klines when added.
 *
 * >irc2.blackened.com NOTICE ToastMON :*** Notice -- ToastMON added K-Line for
 * [fake@another.test.kline]: remove me too by Toast 02/21/97
 * 
 * - Toast
 *
 */

void 
kline_report(char *server_notice)
{
  FILE *fp_log;
  struct tm *broken_up_time;

  broken_up_time = localtime(&current_time);
  
  send_to_all(SEND_KLINE_NOTICES,
	       "*** %s", server_notice);

/* Probably don't need to log klines. --- Toast */
/* I think we need to log everything JIC - Dianora */
/* Logging klines is important -bill */

#ifdef KILL_KLINE_LOG
  if( (fp_log = fopen(KILL_KLINE_LOG,"a")) )
    {
      fprintf(fp_log,"%02d/%02d/%d %02d:%02d %s\n",
	      (broken_up_time->tm_mon)+1,
	      broken_up_time->tm_mday,
	      broken_up_time->tm_year+1900,
	      broken_up_time->tm_hour,
	      broken_up_time->tm_min,
	      server_notice);

      (void)fclose(fp_log);
    }
#endif
}

/*
 * date_stamp(void)
 *
 * inputs	- NONE
 * output	- A pointer to a static char array containing
 *		  a date stamp 
 * side effects	- NONE
 */

char *
date_stamp(void)
{
  struct tm *broken_up_time;
  static char date_stamp_string[SMALL_BUFF];

  broken_up_time = localtime(&current_time);

#ifdef CALVIN
  (void)snprintf(date_stamp_string,
		 sizeof(date_stamp_string) - 1,"%04d%02d%02d",
		 broken_up_time->tm_year+1900,
		 (broken_up_time->tm_mon)+1,
		 broken_up_time->tm_mday);
#else
  (void)snprintf(date_stamp_string,
		 sizeof(date_stamp_string) - 1,"%02d/%02d/%d",
		 (broken_up_time->tm_mon)+1,broken_up_time->tm_mday,
		 broken_up_time->tm_year+1900);
#endif

  return(date_stamp_string);
}

/*
 * tcm_log()
 *
 * inputs	- log level
 *		- format string
 *		- args to format
 * output	- NONE
 * side effects	- log entry is made 
 */

void
tcm_log(int level, const char *format,...)
{
  FILE *l_fp;
  va_list va;

 if(level == L_NORM)
    {
      if ((l_fp = initlog()) == NULL)
	return;
    }
 else if (level == L_WARN)
    {
      if ((l_fp = fopen(WARN_LOG,"a")) == NULL)
	return;
    }
 else if (level == L_ERR)
    {
      if ((l_fp = fopen(ERROR_LOG,"a")) == NULL)
	return;
    }
 else 
   return;

  timestamp_log(l_fp);
  va_start(va,format);
  vfprintf(l_fp, format, va);
  va_end(va);
  fclose(l_fp);
}

/*
 * report_uptime
 *
 * inputs	- socket to print on
 * output	- NONE
 * side effects	- uptime of tcm and opered up time is printed to socket
 */

void 
report_uptime(int sock)
{
  print_to_socket(sock, "*** tcm has been up for %s",
       duration((double) time(NULL)-startup_time));

  print_to_socket(sock, "*** tcm has been opered up for %s",
       duration((double) time(NULL)-oper_time));
}


/*
 * duration
 *
 * inputs	- double time in seconds 
 * output	- uptime formatted
 * side effects	- uptime is formatted
 */

static char *
duration(double a)
{
 int seconds;
 int minutes;
 int hours;
 int days;
 int weeks;
 int years;
 char tmp[SMALL_BUFF];
 static char result[SMALL_BUFF];

 years = a / (60 * 60 * 24 * 365);
 a -= years * 365 * 24 * 60 * 60;
 weeks = a / (60 * 60 * 24 * 7);
 a -= weeks * 60 * 60 * 24 * 7;
 days = a / (60 * 60 * 24);
 a -= days * 60 * 60 * 24;
 hours = a / (60 * 60);
 a -= hours * 60 * 60;
 minutes = a / 60;
 a -= minutes * 60;
 seconds = (int) a % 60;

 result[0] = '\0';

 if (years)
   {
     snprintf(tmp,sizeof(tmp) - 1,"%dy ", years);
     strcat(result, tmp);
   }

 if (weeks)
   {
     snprintf(tmp,sizeof(tmp) - 1,"%dw ", weeks);
     strcat(result, tmp);
   }

 if (days)
   {
     snprintf(tmp,sizeof(tmp) - 1,"%dd ", days);
     strcat(result, tmp);
   }

 if (hours)
   {
     snprintf(tmp,sizeof(tmp) - 1,"%dh ", hours);
     strcat(result, tmp);
   }

 if (minutes)
   {
     snprintf(tmp,sizeof(tmp) - 1,"%dm ", minutes);
     strcat(result, tmp);
   }

 if (seconds)
   {
     snprintf(tmp,sizeof(tmp) - 1,"%ds ", seconds);
     strcat(result, tmp);
   }

 return(result);
}
