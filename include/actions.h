#ifndef __ACTIONS_H
#define __ACTIONS_H

/* $Id: actions.h,v 1.17 2002/12/12 19:30:26 bill Exp $ */

#define MAX_ACTIONS	16

int act_sdrone;
int act_sclone;

int act_drone;
int act_cflood;
int act_vclone;
int act_flood;
int act_link;
int act_bot;
int act_spambot;
int act_clone;
int act_rclone;
int act_jupe;
int act_nflood;

void init_actions(void);
void init_one_action(int *, char *, int, char *);

void set_action(int argc, char *argv[]);

int find_action(char *name);

void handle_action(int actionid,
		   char *nick, char *user, char *host, char *ip,
		   char * addcmt);

char *get_method_names(int method);
char *get_method_userhost(int, char *, char *, char *);

int get_method_number(char * name);
struct a_entry actions[MAX_ACTIONS];

/* Defines for an actions hoststrip field */

/* Mask for the host-only method */
#define HOSTSTRIP_HOST               0x000F
/* Use the full host */
#define HOSTSTRIP_HOST_AS_IS         0x0001 
/* Replace first field of host (or last field of ip) with *   */
#define HOSTSTRIP_HOST_BLOCK         0x0002 

/* Mask for the "if idented" method */
#define HOSTSTRIP_IDENT              0x00F0
/* Use ident as is */
#define HOSTSTRIP_IDENT_AS_IS        0x0010 
/* Use ident as is but prefix with * */
#define HOSTSTRIP_IDENT_PREFIXED     0x0020
/* Replace ident with * */
#define HOSTSTRIP_IDENT_ALL          0x0030

/* Mask for the "if not idented" method */
#define HOSTSTRIP_NOIDENT            0x0F00

/* use ~* */
#define HOSTSTRIP_NOIDENT_ALL_NONE   0x0100
/* Use *username */
#define HOSTSTRIP_NOIDENT_PREFIXED   0x0200
/* Use * */
#define HOSTSTRIP_NOIDENT_ALL        0x0300

/* Methods of handling an event */
#define METHOD_DCC_WARN              0x0001
#define METHOD_IRC_WARN              0x0002
#define METHOD_TKLINE                0x0004
#define METHOD_KLINE                 0x0008
#define METHOD_DLINE                 0x0010


/* Default HOSTSTRIPs */
#define HS_DEFAULT  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL_NONE)

#define HS_CFLOOD   HS_DEFAULT
#define HS_VCLONE   (HOSTSTRIP_HOST_BLOCK | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL_NONE)
#define HS_FLOOD    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_NFLOOD   HS_DEFAULT
#define HS_JUPE     HS_DEFAULT
#define HS_LINK     (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_PREFIXED)
#define HS_SPAMBOT  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_AS_IS | HOSTSTRIP_NOIDENT_ALL)
#define HS_CLONE    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_RCLONE   HS_DEFAULT
#define HS_SCLONE   (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL)
#define HS_DRONE    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_WINGATE  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_SOCKS    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_SQUID    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)

struct a_entry {
  char name[MAX_CONFIG];
  char reason[MAX_CONFIG];
  int method;
  int hoststrip, klinetime;
};

#endif
