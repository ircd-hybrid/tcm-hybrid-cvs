#ifndef __LOGGING_H
#define __LOGGING_H

extern FILE *logging_fp; 
extern FILE *outfile;

void kline_report(char *server_notice);
void log_kline(char *,char *,int ,char *,char *);
void logfailure(char *,int );
void kline_add_report(char *);
void kill_add_report(char *);
char *date_stamp(void);
char *format_reason(char *);
void log(char *format,...);
void log_problem(char *,char *);
void report_uptime(int sock);

#endif
