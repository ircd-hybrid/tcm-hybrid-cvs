#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.23 2002/05/26 17:43:58 leeh Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(char *chan,char *key);
void set_modes(char *chan,char *mode,char *key);
void leave(char *chan);
void newnick(char *nick);
void print_motd(int sock);

/* XXXX go into bothunt.h ? */
void list_nicks(int sock,char *nick,int regex);
void list_virtual_users(int sock,char *userhost,int regex);
void list_users(int sock,char *userhost,int regex);
void kill_list_users(int sock,char *userhost,char *reason,int regex);
void report_multi_host(int sock,int nclones);
void report_multi(int sock,int nclones);
void report_multi_user(int sock,int nclones);
#ifdef VIRTUAL
void report_multi_virtuals(int sock,int nclones);
#endif
void report(int type, int channel_send_flag, char *format,...);
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
void handle_action(int actionid, int idented, char *nick, char *user, char *host, char *ip, char * addcmt);
void initopers(void);
void inithash(void);
void oper();
void report(int type, int channel_report_flag, char *format, ... );

struct s_testline
{
  char umask[MAX_USER+MAX_HOST+2]; /* umask for TESTLINE */
  int index;                       /* index in connections[] of who did command */
};

#endif
