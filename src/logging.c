/*
 * logging.c
 * All the logging type functions moved to here for tcm
 *
 * $Id: logging.c,v 1.54 2002/12/10 16:35:45 bill Exp $
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
#include "hash.h"
#include "logging.h"
#include "stdcmds.h"

time_t startup_time;
time_t oper_time;

FILE *outfile;             /* Debug output file handle
			    * Now shared with writing pid file
			    */


static FILE *initlog(void);
static void timestamp_log(FILE *);
static char *duration(double);


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
log_kline(char *command_name, char *pattern, int  kline_time,
	       char *who_did_command, char *reason)
{
  FILE *fp_log;

#ifdef KILL_KLINE_LOG
  if((fp_log = fopen(KILL_KLINE_LOG,"a")) != NULL)
    {
      if(config_entries.hybrid)
	{
	  if(kline_time)
	    fprintf(fp_log,"%s %s %d %s by %s for %s\n",
		    date_stamp(), command_name, kline_time,
		    pattern, who_did_command, reason);
	  else
	    fprintf(fp_log,"%s %s %s by %s for %s\n",
		    date_stamp(), command_name, pattern, who_did_command,
		    reason);
	}
      else
	{
	  fprintf(fp_log,"%s %s %s by %s for %s\n",
		  date_stamp(), command_name, pattern, who_did_command,
		  reason);
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
 * log_failure()
 *
 * inputs       - pointer to struct user_entry
 * output       - NONE
 * side effects -
 */

void 
log_failure(struct user_entry *userinfo)
{
  struct failrec *ptr;
  struct failrec *hold = NULL;

  for (ptr = failures; ptr; ptr = ptr->next)
    {
      if(!strcasecmp(ptr->username, userinfo->username) && 
	 !strcasecmp(ptr->host, userinfo->host))
        {
          /* For performance, move the most recent to the head of the queue */
          if (hold != NULL)
            {
              hold->next = ptr->next;
              ptr->next = failures;
              failures = ptr;
            }
          break;
        }
      hold = ptr;
    }

  if (ptr == NULL)
    {
      ptr = (struct failrec *)xmalloc(sizeof(struct failrec));

      strlcpy(ptr->username, userinfo->username, MAX_USER);
      strlcpy(ptr->host, userinfo->host, MAX_HOST);
      ptr->failcount = 0;
      ptr->next = failures;
      failures = ptr;
    }
  ++ptr->failcount;
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

  (void)snprintf(date_stamp_string,
		 sizeof(date_stamp_string) - 1,"%04d%02d%02d",
		 broken_up_time->tm_year+1900,
		 (broken_up_time->tm_mon)+1,
		 broken_up_time->tm_mday);

  return(date_stamp_string);
}

/*
 * hour_minute_second
 *
 * inputs	- NULL means provide localtime, otherwise, use given time
 * output	- A pointer to a static char array containing
 *		  hour:minute:second
 * side effects	- NONE
 */

char *
hour_minute_second(time_t time_val)
{
  struct tm *broken_up_time;
  static char time_string[SMALL_BUFF];

  if(time_val == 0)
    broken_up_time = localtime(&current_time);
  else
    broken_up_time = localtime(&time_val);

  (void)snprintf(time_string,
		 sizeof(time_string) - 1,"%2.2d:%2.2d:%2.2d",
		 broken_up_time->tm_hour,
		 broken_up_time->tm_min,
		 broken_up_time->tm_sec);

  return(time_string);
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
  fprintf(l_fp, "\n");
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
report_uptime(struct connection *connection_p)
{
  send_to_connection(connection_p, "*** tcm has been up for %s",
		     duration((double) time(NULL)-startup_time));

  send_to_connection(connection_p, "*** tcm has been opered up for %s",
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
