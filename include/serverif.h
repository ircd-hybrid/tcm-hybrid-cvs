#ifndef __SERVERIF_H
#define __SERVERIF_H

/* $Id: serverif.h,v 1.21 2002/05/24 04:04:17 db Exp $ */

/*
 * default ping timeout time from server
 * note: this value is only used if tcm cannot
 *       determine the ping-frequency value in
 *       the Y: lines.
 */
#define SERVER_TIME_OUT 300
int pingtime;

/*
 * This structure defines who is connected to this tcm.
 */

struct connection {
  char buffer[BUFFERSIZE];
  int  nbuf;			/* number in buffer */
  int  socket;
  int  type;			/* why was this a char? -bill */
  int  set_modes;		/* for set options */
  char user[MAX_USER];
  char host[MAX_HOST];
  char nick[MAX_NICK+2];	/* allow + 2 for incoming tcm names */
  char registered_nick[MAX_NICK+2]; /* allow + 2  */
  time_t last_message_time;
};

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
int  bindsocket(char *);		
void report(int type, int channel_report_flag, char *format, ... );
void sighandlr(int sig);
void closeconn(int, int, char **);
void init_allow_nick();
void oper();
void msg_mychannel(char *msg,...);

#endif
