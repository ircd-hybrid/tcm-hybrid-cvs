#ifndef __LOGGING_H
#define __LOGGING_H

/* $Id: logging.h,v 1.16 2002/06/07 16:32:26 db Exp $ */

extern FILE *outfile;

extern time_t startup_time;
extern time_t oper_time;

struct user_entry;

void log_kline(char *,char *,int ,char *,char *);
void logclear(void);
void log_failure(struct user_entry *userinfo);
void kline_add_report(char *);
char *date_stamp(void);
char *format_reason(char *);
void tcm_log(int level, const char *format,...);
void report_uptime(int sock);

#define L_NORM	0
#define L_WARN	1
#define L_ERR	2

#endif
