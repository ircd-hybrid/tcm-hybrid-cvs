/* tcm_io.h
 *
 * the include files for the tcm IO
 * 
 * $Id: tcm_io.h,v 1.24 2002/05/26 23:33:47 db Exp $
 */
#ifndef __TCM_IO_H
#define __TCM_IO_H

/* Dummy definition for now XXX */
struct sockaddr_in;

/*
 * This structure defines who is connected to this tcm.
 */

struct connection {
  char	buffer[BUFFERSIZE];
  int	nbuf;			/* number in buffer */
  int	socket;
  int   state;
  void	(*io_read_function)(int connect_id);
  void	(*io_write_function)(int connect_id);
  void	(*io_close_function)(int connect_id);
  int	user_state;
  int	type;			/* why was this a char? -bill */
  int	set_modes;		/* for set options */
  char	user[MAX_USER];
  char	host[MAX_HOST];
  char	nick[MAX_NICK+2];	/* allow + 2 for incoming tcm names */
  char	registered_nick[MAX_NICK+2]; /* allow + 2  */
  char	ip[MAX_IP];
  time_t last_message_time;
  /* XXX later */
#if 0
  struct sockaddr_in socketname;
#endif
};

#define	S_IDLE			0
#define	S_CONNECTING		1
#define	S_SERVER		2
#define	S_CLIENT		3

extern struct connection connections[];
int find_free_connection_slot(void);

extern	int initiated_dcc_socket;
extern	time_t initiated_dcc_socket_time;
extern	void initiate_dcc_chat(const char *, const char *, const char *);
void	init_connections(void);
void	close_connection(int connnum);

void notice(const char *nick, const char *format, ...);
void privmsg(const char *target, const char *format, ...);

extern fd_set readfds;
extern fd_set writefds;

extern void read_packet(void);
extern void linkclosed(int, int, char *argv[]);
extern void print_to_socket(int, const char *, ...);
extern void print_to_server(const char *, ...);
/* send_to_all - Hendrix (va'd by bill) */
void send_to_all(int type, const char *format,...);
void send_to_partyline(int conn_num, const char *format,...);

void close_connection(int connect_id);
int connect_to_server(const char *hostport);
int accept_dcc_connection(const char *hostport,
			  const char *nick, char *userhost);
int connect_to_given_ip_port(struct sockaddr_in *, int );

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

#define EOL(c) ((c=='\r')||(c=='\n'))

int pingtime; /* XXX hide later */
#endif
