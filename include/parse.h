/* $Id: parse.h,v 1.4 2002/05/25 23:27:50 db Exp $ */
#ifndef __PARSE_H
#define __PARSE_H



extern void parse_server(void);
extern void parse_client(int, int, char *argv[]);

extern void expand_args(char *, int, int, char *argv[]);
extern int parse_args(char *, char *argv[]);

extern void _wallops(int connnum, int argc, char *argv[]);
extern void _onjoin(int connnum, int argc, char *argv[]);
extern void _signon (int connnum, int argc, char *argv[]);

extern void check_clones(void *);

#ifdef SERVICES
extern void check_services(void *);
extern struct a_entry actions[MAX_ACTIONS+1];
extern int act_drone, act_sclone;
#endif

#endif
