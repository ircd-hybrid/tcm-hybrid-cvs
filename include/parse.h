/* $Id: parse.h,v 1.14 2002/05/28 17:57:07 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H


struct plus_c_info
{
  char *nick;
  char *user;
  char *host;
  char class[MAX_CLASS+1];
  char ip[MAX_IP+1];
};

void parse_server(int);
void parse_client(int);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

struct t_tcm_status {
  char my_nick[MAX_NICK];
  char my_channel[MAX_CHANNEL];
  char my_hostname[MAX_HOST];   /* This is our hostname with domainname */
  char my_class[MAX_CLASS];
  char serverhost[MAX_HOST];    /* Server tcm will use. */
  int  am_opered;
  int  pingtime;
};

extern struct t_tcm_status tcm_status;

#endif
