#ifndef __LOGGING_H
#define __LOGGING_H

/* $Id: logging.h,v 1.10 2002/05/27 23:59:42 db Exp $ */

extern FILE *logging_fp; 
extern FILE *outfile;

void kline_report(char *snotice);
void log_kline(char *,char *,int ,char *,char *);
void logclear(void);
void logfailure(char *,int );
void kline_add_report(char *);
char *date_stamp(void);
char *format_reason(char *);
void tcm_log(int level, const char *format,...);
void report_uptime(int sock);
void chopuh(int istrace,char *nickuserhost,struct plus_c_info *userinfo);

#define L_NORM	0
#define L_WARN	1
#define L_ERR	2

#endif
