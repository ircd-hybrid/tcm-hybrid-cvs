#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.26 2002/05/28 12:48:29 leeh Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(void);
void leave(char *chan);
void newnick(char *nick);
void print_motd(int sock);

void do_a_kline(char *command_name,int kline_time, char *pattern, char *reason,
                char *who_did_command);

void initopers(void);
void inithash(void);
void oper();

struct s_testline
{
  char umask[MAX_USER+MAX_HOST+2]; /* umask for TESTLINE */
  int index;                       /* index in connections[]
				    * of who did command
				    */
};

#endif
