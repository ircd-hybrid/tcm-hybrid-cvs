/* tcm_io.h
 *
 * the include files for the tcm IO
 * 
 * $Id: tcm_io.h,v 1.44 2002/06/24 16:21:48 leeh Exp $
 */
#ifndef __TCM_IO_H
#define __TCM_IO_H

#include "tools.h"

/* Dummy definition for now XXX */
struct sockaddr_in;

/*
 * This structure defines who is connected to this tcm.
 */

struct connection {
  char	buffer[BUFFERSIZE];
  int	nbuf;			/* number in buffer */
  int	socket;
  int	conn_num;		/* old connnum */
  int   state;                  /* indicates type of connection */
  int	curr_state;             /* indicates sent ping, socks etc */
  void	(*io_read_function)(struct connection *);
  void	(*io_write_function)(struct connection *);
  void	(*io_close_function)(struct connection *);
  void	(*io_timeout_function)(struct connection *);
  int	set_modes;		/* for set options */
  char	username[MAX_USER];
  char	host[MAX_HOST];
  char	nick[MAX_NICK];
  char	registered_nick[MAX_NICK];
  char	ip[MAX_IP];
  time_t last_message_time;
  int	time_out;		/* 0 for no time out */
  int   type;
  /* XXX later ? */
#if 0
  struct sockaddr_in socketname;
#endif
};

#define	S_IDLE			0
#define	S_CONNECTING		1
#define	S_SERVER		2
#define	S_CLIENT		3

struct dlink_list;
dlink_list connections;

struct connection *find_free_connection(void);

void init_connections(void);

void server_link_closed(struct connection *uplink);
void close_connection(struct connection *connection_p);

void notice(const char *nick, const char *format, ...);
void privmsg(const char *target, const char *format, ...);

extern fd_set readfds;
extern fd_set writefds;

void read_packet(void);
void client_link_closed(struct connection *, const char *format, ...);
void send_to_connection(struct connection *, const char *, ...);
void send_to_server(const char *, ...);
/* send_to_all - Hendrix (va'd by bill) */
void send_to_all(int type, const char *format,...);
void send_to_partyline(struct connection *, const char *format,...);

struct connection *connect_to_server(const char *server, const int port);
int connect_to_given_ip_port(struct sockaddr_in *, int );

#define EOL(c) ((c=='\r')||(c=='\n'))

struct connection *find_user_in_connections(const char *);
void list_connections(struct connection *);
#endif
