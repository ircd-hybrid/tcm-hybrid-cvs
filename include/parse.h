/* $Id: parse.h,v 1.19 2002/06/04 05:54:02 db Exp $ */
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
  int  am_opered;
  int  ping_time;
  int  doing_trace;		/* presently doing trace */
  int  ping_state;		/* ping to server */
};

#define S_PINGSENT		1

extern struct t_tcm_status tcm_status;

#endif
