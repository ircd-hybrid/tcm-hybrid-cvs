/* $Id: parse.h,v 1.17 2002/06/03 20:22:25 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H

void parse_server(int);
void parse_client(int);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

struct t_tcm_status {
  char my_nick[MAX_NICK];
  char my_channel[MAX_CHANNEL];
  char my_hostname[MAX_HOST];	/* This is our hostname with domainname */
  char my_class[MAX_CLASS];
  char server_host[MAX_HOST];	/* Server tcm will use. */
  int  am_opered;
  int  ping_time;
  int  doing_trace;		/* presently doing trace */
};

extern struct t_tcm_status tcm_status;

#endif
