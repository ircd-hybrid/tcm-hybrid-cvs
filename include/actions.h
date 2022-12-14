#ifndef __ACTIONS_H
#define __ACTIONS_H

/* $Id: actions.h,v 1.24 2004/06/11 20:05:48 bill Exp $ */

#define MAX_ACTIONS	16

struct a_entry {
  char name[MAX_CONFIG+1];
  char reason[MAX_CONFIG+1];
  int method;
  int hoststrip;
  int klinetime;
};

struct a_entry actions[MAX_ACTIONS];

int act_sclone;
int act_drone;
int act_cflood;
int act_vclone;
int act_flood;
int act_link;
int act_spam;
int act_clone;
int act_rclone;
int act_jupe;
int act_nflood;

void init_actions(void);
void init_one_action(int *, char *, int, char *);

void set_action(int, char *[]);

int find_action(char *);

void handle_action(int, char *, char *, char *, char *, char *);

char *get_method_names(int);
char *get_method_userhost(int, char *, char *, char *);

int get_method_number(char *);

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
#define METHOD_SKLINE                0x0004
#define METHOD_KLINE                 0x0008
#define METHOD_DLINE                 0x0010


/* Default HOSTSTRIPs */
#define HS_DEFAULT  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL_NONE)

#define HS_CFLOOD   HS_DEFAULT
#define HS_VCLONE   (HOSTSTRIP_HOST_BLOCK | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL_NONE)
#define HS_FLOOD    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_NFLOOD   HS_DEFAULT
#define HS_JUPE     (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_LINK     (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_PREFIXED)
#define HS_SPAM     (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_AS_IS | HOSTSTRIP_NOIDENT_ALL)
#define HS_CLONE    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_RCLONE   HS_DEFAULT
#define HS_SCLONE   (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL)
#define HS_DRONE    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)

#endif
