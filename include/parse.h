/* $Id: parse.h,v 1.10 2002/05/27 05:03:11 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H



void parse_server(int);
void parse_client(int);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

/* XXX does not belong here */
void check_clones(void *);

extern struct a_entry actions[MAX_ACTIONS+1];

#endif
