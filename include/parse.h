/* $Id: parse.h,v 1.23 2002/06/24 00:40:15 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H

struct connection;

void parse_server(struct connection *);
void parse_client(struct connection *);
void expand_args(char *, int, int, char *argv[]);

struct t_tcm_status {
  char my_nick[MAX_NICK];
  char my_channel[MAX_CHANNEL];
  char my_hostname[MAX_HOST];	/* This is our hostname with domainname */
  char my_server[MAX_HOST];
  char my_class[MAX_CLASS];
  int  am_opered;
  int  ping_time;
  int  doing_trace;		/* presently doing trace */
  int  ping_state;		/* ping to server */
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
