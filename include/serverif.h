#ifndef __SERVERIF_H
#define __SERVERIF_H

/* $Id: serverif.h,v 1.24 2002/05/25 16:27:25 jmallett Exp $ */

/*
 * default ping timeout time from server
 * note: this value is only used if tcm cannot
 *       determine the ping-frequency value in
 *       the Y: lines.
 */
#define SERVER_TIME_OUT 300
int pingtime;


#ifndef OPERS_ONLY
extern int isbanned(char *,char *);
#endif

char myclass[100];

/*
 * services struct
 * Used to store info about global clones derived from services.us
 */

struct services_entry
{
  char   cloning_host[MAX_HOST];
  char   last_cloning_host[MAX_HOST];
  char   user_count[SMALL_BUFF];
  int    clones_displayed;
  int    kline_suggested;
};

void do_init(void);		
void report(int type, int channel_report_flag, char *format, ... );
void sighandlr(int sig);
void closeconn(int);
void init_allow_nick();
void oper();
void msg_mychannel(char *msg,...);

#endif
