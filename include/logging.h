#ifndef __LOGGING_H
#define __LOGGING_H

/* $Id: logging.h,v 1.7 2002/05/27 00:42:10 db Exp $ */

extern FILE *logging_fp; 
extern FILE *outfile;

void kline_report(char *snotice);
void log_kline(char *,char *,int ,char *,char *);
void logclear(void);
void logfailure(char *,int );
void kline_add_report(char *);
void kill_add_report(char *);
char *date_stamp(void);
char *format_reason(char *);
void log(const char *format,...);
void log_problem(const char *format, ...);
void report_uptime(int sock);

#endif
