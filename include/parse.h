/* $Id: parse.h,v 1.27 2004/06/11 20:05:48 bill Exp $ */
#ifndef __PARSE_H
#define __PARSE_H

struct connection;

void parse_server(struct connection *);
void parse_client(struct connection *);
void expand_args(char *, int, int, char *argv[]);

#define PRIV_XLINE	0x001
#define PRIV_DLINE	0x002
#define PRIV_GLINE	0x004
#define PRIV_KLINE	0x008
#define PRIV_NKCHG	0x010
#define PRIV_GKILL	0x020
#define PRIV_ROUTE	0x040
#define PRIV_UNLNE	0x080
#define PRIV_ADMIN	0x100
#define PRIV_DIE	0x200

struct t_tcm_status {
  char my_nick[MAX_NICK+1];
  char my_channel[MAX_CHANNEL+1];
  char my_hostname[MAX_HOST+1];	/* This is our hostname with domainname */
  char my_server[MAX_HOST+1];
  char my_class[MAX_CLASS+1];
  int  am_opered;
  int  ping_time;
  int  doing_trace;		/* presently doing trace */
  int  ping_state;		/* ping to server */
  int  n_of_fds_open;
  int  max_fds;
  int  oper_privs;
};

struct source_client
{
  char *name;
  char *username;
  char *host;
};

#define S_PINGSENT		1

extern struct t_tcm_status tcm_status;

#endif
