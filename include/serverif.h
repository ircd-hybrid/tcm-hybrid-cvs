#ifndef __SERVERIF_H
#define __SERVERIF_H

/* $Id: serverif.h,v 1.12 2001/11/02 16:53:08 db Exp $ */

/* Time out for no response from the server 
 * 5 minutes should be plenty to receive a PING from the server
 */
#define SERVER_TIME_OUT 300

time_t cur_time;

/*
 * This structure defines who is connected to this tcm.
 */

struct connection {
  char *buffer;
  char *buffend;
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

/*
 * services struct
 * Used to store info about global clones derived from services.us
 */

struct services_entry
{
  time_t last_checked_time;
  char   cloning_host[MAX_HOST];
  char   last_cloning_host[MAX_HOST];
  char   user_count[SMALL_BUFF];
  int    clones_displayed;
  int    kline_suggested;
};

void prnt(int,...);		/* - Hendrix (va'd by bill)*/

void do_init(void);		
int  bindsocket(char *);		
void toserv(char *,...);	
void sendtoalldcc(int type,char *format,...);	/* - Hendrix (va'd by bill) */
void report(int type, int channel_report_flag, char *format, ... );
void sighandlr(int sig);
void gracefuldie(int, char*, int);	
char makeconn(char *,char *,char *);
void closeconn(int, int, char **);
void init_allow_nick();

void init_remote_tcm_listen(void);
void sendto_all_linkedbots(char *);

void oper();
void msg_mychannel(char *msg,...);

void rdpt(void);
void linkclosed(int connnum, int argc, char *argv[]);
void _wallops(int connnum, int argc, char *argv[]);
void _onjoin(int connnum, int argc, char *argv[]);
void _signon (int connnum, int argc, char *argv[]);
void _modinit();

/* types for sendtoalldcc */

#define SEND_ALL_USERS	0
#define SEND_OPERS_ONLY	1
#define SEND_OPERS_PRIVMSG_ONLY 2
#define SEND_OPERS_NOTICES_ONLY 3
#define SEND_OPERS_STATS_ONLY 4
#define SEND_WALLOPS_ONLY 5
#define SEND_LOCOPS_ONLY 6
#define SEND_WARN_ONLY 7
#define SEND_LINK_ONLY 8
#define SEND_MOTD_ONLY 9
#define SEND_KLINE_NOTICES_ONLY 10
#define SEND_ADMIN_ONLY 11
#define SEND_OPERWALL_ONLY 12

/* wait five minutes after last PING before figuring server is stoned */
#define PING_OUT_TIME 300

#endif
