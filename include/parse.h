/* $Id: parse.h,v 1.12 2002/05/28 16:41:52 db Exp $ */
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

extern char mynick[MAX_NICK];
extern char ourhostname[MAX_HOST];   /* This is our hostname with domainname */
extern char serverhost[MAX_HOST];    /* Server tcm will use. */
extern int  amianoper;

#endif
