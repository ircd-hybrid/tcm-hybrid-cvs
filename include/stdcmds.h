#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.32 2002/06/24 00:40:15 db Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(void);
void leave(char *chan);
void newnick(char *nick);
void print_motd(struct connection *connection_p);
void report(int type, char *format,...);

void do_a_kline(int kline_time, char *pattern, char *reason,
                char *who_did_command);

void init_hash(void);
void oper();

struct s_testline
{
  char umask[MAX_USERHOST]; /* umask for TESTLINE */
  int index;                       /* index in connections[]
				    * of who did command
				    */
};

#endif
