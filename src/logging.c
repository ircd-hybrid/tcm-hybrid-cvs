/*
 * logging.c
 * All the logging type functions moved to here for tcm
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

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#ifdef AIX
# include <sys/select.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "config.h"
#include "tcm.h"
#include "userlist.h"
#include "serverif.h"
#include "bothunt.h"
#include "logging.h"

static char *version="$Id: logging.c,v 1.2 2000/09/02 05:42:37 lusky Exp $";

FILE *outfile;             /* Debug output file handle
			    * Now shared with writing pid file
			    */

extern struct failrec *failures;
extern struct connection connections[];

static FILE *initlog(void);
static void timestamp_log(FILE *);
static char *durtn(double);

/*
 * initlog()
 *
 * inputs - NONE
 * output - NONE
 * side effects
 *
 */

static FILE *initlog(void)
{
  time_t current_time;
  struct tm *broken_up_time;
  char filename[MAX_BUFF];
  char command[MAX_BUFF];
  char last_filename[MAX_BUFF];
  char *p;
  FILE *last_log_fp;
  FILE *email_fp;
  FILE *log_to_email_fp;
  FILE *logging_fp;

#ifdef LOGFILE
  last_filename[0] = '\0';

  if( (last_log_fp = fopen(LAST_LOG_NAME,"r")) )
    {
      (void)fgets(last_filename,MAX_BUFF-1,last_log_fp);
      if( (p = strchr(last_filename,'\n')) )
	*p = '\0';

      if(config_entries.debug && outfile)
	{
	  fprintf(outfile, "last_filename = [%s]\n", last_filename );
	}
      (void)fclose(last_log_fp);
    }

  current_time = time((time_t *)NULL);
  broken_up_time = localtime(&current_time);

  (void)sprintf(filename,"%s_%02d_%02d_%04d",LOGFILE,
		(broken_up_time->tm_mon)+1,broken_up_time->tm_mday,
		broken_up_time->tm_year + 1900);

  if( !(logging_fp = fopen(filename,"a")) )
    return (FILE *)NULL;

  if(!config_entries.email_config[0])
    return (FILE *)NULL;

  if( !last_filename[0] )
    {
      strcpy(last_filename,filename);
    }

#ifdef HOW_TO_MAIL
  if( !(strcmp(last_filename,filename)) )
    {
      (void)sprintf(command,"%s \"clone report\" %s",HOW_TO_MAIL,
		    config_entries.email_config);
      if( (email_fp = popen(command,"w")) )
	{
	  if( (log_to_email_fp = fopen(last_filename,"r")) )
	    {
	      while(fgets(command,MAX_BUFF-1,log_to_email_fp ))
		fputs(command,email_fp);
	      (void)fclose(log_to_email_fp);
	    }
	  (void)fclose(email_fp);
	}
      (void)unlink(last_filename);
    }
#endif
  if( (last_log_fp = fopen(LAST_LOG_NAME,"w")) )
    {
      (void)fputs(filename,last_log_fp);
      (void)fclose(last_log_fp);
    }
#else
  logging_fp = (FILE *)NULL;
#endif

  return logging_fp;
}

/*
 * timestamp_log()
 *
 * inputs - NONE
 * output - NONE
 * side effects
 *
 */

void timestamp_log(FILE *fp)
{
  time_t current_time;
  struct tm *broken_up_time;

  if(!fp)
    return;

  current_time = time((time_t *)NULL);
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

void log_kline(char *command_name,
	       char *pattern,
	       int  kline_time,
	       char *who_did_command,
	       char *reason)
{
  time_t current_time;
  struct tm *broken_up_time;
  FILE *fp_log;

  current_time = time((time_t *)NULL);
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
 * logfailure()
 *
 * inputs	- pointer to nick!user@host
 *		- if a bot reject or not
 * output	- NONE
 * side effects	- 
 */

void logfailure(char *nickuh,int botreject)
{
  struct plus_c_info userinfo;
  struct failrec *tmp, *hold = NULL;

  chopuh(YES,nickuh,&userinfo); /* use trace form of chopuh() */

  tmp = failures;
  while (tmp)
    {
      if(!strcasecmp(tmp->user,userinfo.user)&&!strcasecmp(tmp->host,
							   userinfo.host))
	{
	  /* For performance, move the most recent to the head of the queue */
	  if (hold)
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

  if (!tmp)
    {
      tmp = (struct failrec *)malloc(sizeof(struct failrec));
      if(tmp == (struct failrec *)NULL)
	{
	  prnt(connections[0].socket,"Ran out of memory in logfailure\n");
	  sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in logfailure");
	  gracefuldie(0, __FILE__, __LINE__);
	}

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
 * kline_add_report
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

void kline_add_report(char *server_notice)
{
  FILE *fp_log;
  time_t current_time;
  struct tm *broken_up_time;

  current_time = time((time_t *)NULL);
  broken_up_time = localtime(&current_time);
  
  sendtoalldcc(SEND_KLINE_NOTICES_ONLY, "*** %s", server_notice);

/* Probably don't need to log klines. --- Toast */
/* I think we need to log everything JIC - Dianora */
/* Logging klines is important - pro */

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
 * kill_add_report
 *
 * input	- server notice
 * output	- none
 * side effects	- local kills are logged
 *
 *  Log only local kills though....
 *
 *** Notice -- Received KILL message for Newbie2. From Dianora_ Path:
 *  ts1-4.ottawa.net!Dianora_ (clone)
 * Thanks Thembones for bug fix (Brian Kraemer kraemer@u.washington.edu)
 */

void kill_add_report(char *server_notice)
{
char *path;
char *p, *from;
int number_of_bangs = 0;

  if( !(from = strstr(server_notice,". From ")) )
    return;	

  /* Now check the killer's name for a . */
  for (p = (from += 7); ((*p) && (*p != ' ')); p++)
    if (*p == '.')			/* Ignore Server kills */
      return;

  if( !(path = strstr(server_notice,"Path:")) )
    return;

  p = path;
  while(*p)
    {
      if(*p == '!')
        {
          number_of_bangs++;
          if( number_of_bangs > 1)return;
        }
      p++;
    }

  kline_add_report(server_notice);
}

/*
 * date_stamp(void)
 *
 * inputs	- NONE
 * output	- A pointer to a static char array containing
 *		  a date stamp 
 * side effects	- NONE
 */

char *date_stamp(void)
{
  time_t current_time;
  struct tm *broken_up_time;
  static char date_stamp_string[SMALL_BUFF];

  current_time = time((time_t *)NULL);
  broken_up_time = localtime(&current_time);

#ifdef CALVIN
  (void)sprintf(date_stamp_string,"%04d%02d%02d",
		broken_up_time->tm_year+1900,
		(broken_up_time->tm_mon)+1,
		broken_up_time->tm_mday);
#else
  (void)sprintf(date_stamp_string,"%02d/%02d/%d",
		(broken_up_time->tm_mon)+1,broken_up_time->tm_mday,
		broken_up_time->tm_year+1900);
#endif

  return(date_stamp_string);
}

/*
 * log_problem()
 *
 * inputs	- function name to report
 *		  reason of problem
 * output	- NONE
 * side effects	- log entry is made 
 */

void log_problem(char *function_name,char *reason)
  {
    FILE *error_fp;

    if( (error_fp = fopen(ERROR_LOG,"a")) )
      {
	timestamp_log(error_fp);
	(void)fprintf(error_fp,"%s - %s\n",function_name, reason);
	(void)fclose(error_fp);
      }
  }

/*
 * log()
 *
 * inputs	- format string
 *		- args to format
 * output	- NONE
 * side effects	- log entry is made 
 */

void log(char *format,...)
{
  char msg[MAX_BUFF];
  FILE *logging_fp;
  va_list va;

  va_start(va,format);

  if( (logging_fp = initlog()) )
    {
      timestamp_log(logging_fp);
      vsnprintf(msg,sizeof(msg),format, va);

      fputs(msg,logging_fp);
      (void)fclose(logging_fp);
    }
  va_end(va);
}

/*
 * report_uptime
 *
 * inputs	- socket to print on
 * output	- NONE
 * side effects	- uptime of tcm and opered up time is printed to socket
 */

void report_uptime(int socket)
{
  prnt(socket, "*** tcm has been up for %s\n",
       durtn((double) time(NULL)-startup_time));

  prnt(socket, "*** tcm has been opered up for %s\n",
       durtn((double) time(NULL)-oper_time));
}


/*
 * durtn
 *
 * inputs	- double time in seconds 
 * output	- uptime formatted
 * side effects	- uptime is formatted
 */

static char *durtn(double a)
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
     sprintf(tmp, "%dy ", years);
     strcat(result, tmp);
   }

 if (weeks)
   {
     sprintf(tmp, "%dw ", weeks);
     strcat(result, tmp);
   }

 if (days)
   {
     sprintf(tmp, "%dd ", days);
     strcat(result, tmp);
   }

 if (hours)
   {
     sprintf(tmp, "%dh ", hours);
     strcat(result, tmp);
   }

 if (minutes)
   {
     sprintf(tmp, "%dm ", minutes);
     strcat(result, tmp);
   }

 if (seconds)
   {
     sprintf(tmp, "%ds ", seconds);
     strcat(result, tmp);
   }

 return(result);
}



