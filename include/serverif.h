#ifndef __SERVERIF_H
#define __SERVERIF_H

/* Time out for no response from the server 
 * 5 minutes should be plenty to receive a PING from the server
 */
#define SERVER_TIME_OUT 300

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

extern struct connection connections[];

#define WINGATE_CONNECTING 1
#define WINGATE_READING 2
#define WINGATE_READ 3
#define SOCKS_CONNECTING 4

#ifndef OPERS_ONLY
extern int isbanned(char *,char *);
#endif

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
struct wingates {
  char user[MAX_USER];
  char host[MAX_HOST];
  char nick[MAX_NICK+2];	/* allow + 2 for incoming bot names */
  int  socket;
  int  state;
  time_t connect_time;
  struct sockaddr_in socketname;
  };
#endif

struct 
{
  char to_nick[MAX_NICK+1];
  char to_tcm[MAX_NICK+1];
  char from_nick[MAX_NICK+1];
  char from_tcm[MAX_NICK+1];
}route_entry;

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
void sendtoalldcc(int type,...);	/* - Hendrix (va'd by bill) */
void report(int type, int channel_report_flag, char *format, ... );
void sighandlr(int sig);
void gracefuldie(int, char*, int);	
char makeconn(char *,char *,char *);
void closeconn(int);
void init_allow_nick();

void init_remote_tcm_listen(void);
void sendto_all_linkedbots(char *);
int  add_connection(int,int);
int  already_have_tcm(char *);

#ifdef DETECT_WINGATE
int wingate_bindsocket(char *,char *,char *,char *);
extern struct wingates wingate[];
#endif

#ifdef DETECT_SOCKS
int socks_bindsocket(char *,char *,char *,char *);
extern struct wingates socks[];
#endif

void oper();
void msg_mychannel(char *msg,...);

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

/* wait five minutes after last PING before figuring server is stoned */
#define PING_OUT_TIME 300

#endif








