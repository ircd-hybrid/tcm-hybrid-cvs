/* $Id: parse.h,v 1.6 2002/05/26 01:28:17 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H



void parse_server(void);
int parse_client(int, int, char *argv[]);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

void _wallops(int connnum, int argc, char *argv[]);
void _onjoin(int connnum, int argc, char *argv[]);
void _signon (int connnum, int argc, char *argv[]);

void check_clones(void *);

extern struct a_entry actions[MAX_ACTIONS+1];

#endif
