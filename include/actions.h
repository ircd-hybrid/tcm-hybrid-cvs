#ifndef __ACTIONS_H
#define __ACTIONS_H

/* $Id: actions.h,v 1.1 2002/05/27 21:02:30 db Exp $ */

void handle_action(int actionid, int idented,
		   char *nick, char *user, char *host, char *ip,
		   char * addcmt);


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
/* Use *~* */
#define HOSTSTRIP_NOIDENT_UNIDENTED  0x0100 
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
#define HS_DEFAULT  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL)

#define HS_CFLOOD   HS_DEFAULT
#define HS_VCLONE   (HOSTSTRIP_HOST_BLOCK | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL)
#define HS_FLOOD    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_LINK     HS_DEFAULT
#define HS_BOT      HS_DEFAULT
#define HS_SPAMBOT  HS_DEFAULT
#define HS_CLONE    HS_DEFAULT
#define HS_RCLONE   HS_DEFAULT
#define HS_SCLONE   HS_DEFAULT
#define HS_DRONE    HS_DEFAULT
#define HS_WINGATE  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_SOCKS    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_SQUID    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)

struct a_entry {
  char name[MAX_CONFIG];
  char reason[MAX_CONFIG];
  int method;
  int hoststrip, klinetime;
};

struct a_entry actions[MAX_ACTIONS+1];

char * get_method_names(int method);
int get_method_number(char * name);

#endif
