/* $Id: parse.h,v 1.7 2002/05/26 02:12:43 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H



int parse_server(int);
int parse_client(int);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

void _wallops(int connnum, int argc, char *argv[]);
void _onjoin(int connnum, int argc, char *argv[]);

void check_clones(void *);

extern struct a_entry actions[MAX_ACTIONS+1];

#endif
