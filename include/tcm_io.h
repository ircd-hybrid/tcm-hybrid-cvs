/* tcm_io.h
 *
 * the include files for the tcm IO
 * 
 * $Id: tcm_io.h,v 1.7 2002/05/24 18:29:16 leeh Exp $
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
void send_to_all(int type, const char *format,...);	/* - Hendrix (va'd by bill) */

/* types for send_to_all */

#define SEND_ALL		0x001 /* general messages */
#define SEND_PRIVMSG		0x002 /* users privmsging tcm */
#define SEND_NOTICES		0x004 /* users noticing tcm */
#define SEND_WALLOPS		0x008 /* wallops and operwall */
#define SEND_LOCOPS		0x010 /* locops */
#define SEND_WARN		0x020 /* warning messages (clones etc) */
#define SEND_SPY		0x040 /* motd, links, info, stats requests */
#define SEND_KLINE_NOTICES	0x080 /* klines/unklines */
#define SEND_ADMINS		0x100 /* admin stuff like modload */
#define SEND_SERVERS		0x200 /* server splits/joins */

#endif
