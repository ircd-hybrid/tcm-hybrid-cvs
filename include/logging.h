#ifndef __LOGGING_H
#define __LOGGING_H

/* $Id: logging.h,v 1.17 2002/06/22 14:04:44 db Exp $ */

extern FILE *outfile;

extern time_t startup_time;
extern time_t oper_time;

struct user_entry;

void log_kline(char *,char *,int ,char *,char *);
void logclear(void);
void log_failure(struct user_entry *userinfo);
void kline_add_report(char *);
char *date_stamp(void);
char *hour_minute_second(time_t time_val);
char *format_reason(char *);
void tcm_log(int level, const char *format,...);
void report_uptime(int sock);

#define L_NORM	0
#define L_WARN	1
#define L_ERR	2

#endif
