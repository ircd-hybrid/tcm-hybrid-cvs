/* $Id: parse.h,v 1.8 2002/05/26 02:32:44 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H



void parse_server(int);
void parse_client(int);

void expand_args(char *, int, int, char *argv[]);
int parse_args(char *, char *argv[]);

void _wallops(int connnum, int argc, char *argv[]);
void _onjoin(int connnum, int argc, char *argv[]);

void check_clones(void *);

extern struct a_entry actions[MAX_ACTIONS+1];

#endif
