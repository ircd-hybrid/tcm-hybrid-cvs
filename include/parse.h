/* $Id: parse.h,v 1.9 2002/05/27 02:59:25 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H



void parse_server(int);
void parse_client(int);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

void _onjoin(int connnum, int argc, char *argv[]);

void check_clones(void *);

extern struct a_entry actions[MAX_ACTIONS+1];

#endif
