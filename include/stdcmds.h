#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.14 2002/05/03 22:49:43 einride Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(char *chan,char *key);
void leave(char *chan);
void notice(char *nick,...);
void privmsg(char *nick,...);
void newnick(char *nick);
void print_motd(int sock);
void list_nicks(int sock,char *nick,int regex);
void list_virtual_users(int sock,char *userhost,int regex);
void list_users(int sock,char *userhost,int regex);
void kill_list_users(int sock,char *userhost,char *reason,int regex);
void report_mem(int sock);
void report_clones(int sock);
void report_nick_flooders(int sock);
void report_vbots(int sock,int nclones);
void report_domains(int sock,int num);
void report_failures(int sock,int num);
void do_a_kline(char *command_name,int kline_time, char *pattern, char *reason,
                char *who_did_command);
void list_class(int sock,char *class_to_find,int total_only);
/*
xxx_ void suggest_action(int type_s, char *nick, char *user, char *host,
                    int different, int identd);
*/
void handle_action(int action, int idented, char *nick, char *user, char *host, char *ip);
void initopers(void);
void inithash(void);
void prnt(int,char *,...);              /* - Hendrix (va'd by bill)*/

struct s_testline
{
  char umask[MAX_USER+MAX_HOST+2]; /* umask for TESTLINE */
  int index;                       /* index in connections[] of who did command */
};

#endif
