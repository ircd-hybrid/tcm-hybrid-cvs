#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.31 2002/06/21 16:46:43 leeh Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(void);
void leave(char *chan);
void newnick(char *nick);
void print_motd(int sock);
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
