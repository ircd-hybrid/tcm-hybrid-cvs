/* tcm_io.h
 *
 * the include files for the tcm IO
 * 
 * $Id: tcm_io.h,v 1.3 2002/05/24 04:04:17 db Exp $
 */
#ifndef __TCM_IO_H
#define __TCM_IO_H

extern int initiated_dcc_socket;
extern time_t initiated_dcc_socket_time;
extern void initiate_dcc_chat(char *, char *, char *);

extern fd_set readfds;
extern fd_set writefds;

extern void read_packet(void);
extern void linkclosed(int, int, char *argv[]);

extern void print_to_socket(int, const char *, ...);
extern void print_to_server(const char *, ...);
void sendtoalldcc(int incoming_connum,
		  int type,char *format,...);	/* - Hendrix (va'd by bill) */

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
#define SEND_SERVERS_ONLY 13

#endif
