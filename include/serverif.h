#ifndef __SERVERIF_H
#define __SERVERIF_H

/* $Id: serverif.h,v 1.26 2002/05/26 01:28:17 db Exp $ */

/*
 * default ping timeout time from server
 * note: this value is only used if tcm cannot
 *       determine the ping-frequency value in
 *       the Y: lines.
 */
#define SERVER_TIME_OUT 300
int pingtime;


char myclass[100];

void do_init(void);		
void report(int type, int channel_report_flag, char *format, ... );
void sighandlr(int sig);
void init_allow_nick();
void oper();
void msg_mychannel(char *msg,...);

#endif
