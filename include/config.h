#ifndef __CONFIG_H
#define __CONFIG_H

/*
 * tcm config.h
 * Global definitions obtained by including this file.
 *
 * $Id: config.h,v 1.91 2004/06/09 21:22:58 bill Exp $
 */

/*
 * VIRTUAL, watch for clones from v hosted sites
 * only works on hybrid servers 5.1 and up
 */
#define VIRTUAL

/*
 * IPV6: this is still not tested very much and may eat
 *       your tcm for breakfast and kline all your users
 *       with the message "fek u", but here it is!  -wiz
 */
#undef IPV6
#undef VIRTUAL_IPV6

/*
 * AGGRESSIVE_GECOS, define this if you want your tcm to
 * perform a WHO on all users, building a gecos listing.
 * WARNING! This can severly lag your tcm on larger servers
 */
#define AGGRESSIVE_GECOS

/*
 * USE_CRYPT, define this if you want your oper passwords to be encrypted
 */
#define USE_CRYPT

/*
 * if you like the tcm to report its users on stats p, define this
 */
#define STATS_P

/* 
 * if you want to hide oper's hosts in /stats p responses, define this.  -jds 6/28/00
 */
#undef HIDE_OPER_HOST

/* 
 * if you want to hide the oper doing the klines to users, define this.
 * Note: the user will still show up in DCC and in the logs.
 */
#undef HIDE_OPER_IN_KLINES

/*
 *  If you don't like the idea of any remote oper including those on the
 *  tcm, being able to D line, define this
 */
#undef NO_D_LINE_SUPPORT

/*
 * The default tcm config file, can be overridden with a file name
 * argument to tcm.
 */
#define CONFIG_FILE "etc/tcm.conf"

/*
 * The default tcm dynamic hostlist file.  This can be overridden
 * in the tcm.conf
 */
#define SKLINE_FILE "etc/dynamic.hosts"

#define HELP_PATH "help"        /* No / at the end */
#define HELP_FILE "help"        /* Inside of HELP_PATH */
#define MOTD_FILE "etc/tcm.motd"

#define LOGFILE "logs/tcm.log"
#define LAST_LOG_NAME "logs/last_log_name"

/* Where nasty errors are logged */
#define ERROR_LOG "logs/error.log"

/* Where warnings are logged */
#define WARN_LOG "logs/warnings.log"

#define KILL_KLINE_LOG "logs/kills_klines.log"

#define DEBUG_LOGFILE "logs/tcm.log"

/* How to email, sendmail would work too */
/* This is obviously a SUNos ism */
/* note:  if you do not want to have this support enabled, do not define */
/* #define HOW_TO_MAIL "/usr/ucb/mail -s" */

/* For Linux this is suggested by zaph */
/* #define HOW_TO_MAIL "/bin/mail -s" */

/* For FreeBSD and OpenBSD, this is suggested by zartik */
/* #define HOW_TO_MAIL "/usr/bin/mail -s" */

/* Lifetime, in seconds, of client lists
   Leave undefined if you do not want list expiration */
#define CLIENT_LIST_LIFE	(60 * 60 * 3)

/*
 * tcm normally catches clones because they rapidly connect, and
 * this is noticed. If a wily clone runner wanted to, they could
 * connect slowly enough that the cloning isn't noticed.
 * tcm now has code to automatically scan for clones,
 * both CLONE_CHECK_TIME and MIN_CLONE_NUMBER are used for this check
 */

/*
 * length of time between scans of tcm's internal user table
 * for detection of clones
 *
 * This time is in seconds
 */
#define CLONE_CHECK_TIME 60

/*
 * Minimum number of clients to report as clones
 */
#define MIN_CLONE_NUMBER 4

/*
 * Minimum number of matches to be reported in .multi functions
 */
#define MULTI_MIN 3

/*
 * These are the defaults, if no actions are given in tcm.cf
 */

/* Now, all the KLINE reasons are defines i.e. the kline
for .kflood would be the #define for REASON_FLOOD etc. */

#define REASON_CFLOOD  "Connection flooding"
#define REASON_VCLONE  "V-hosted clones"
#define REASON_FLOOD   "Flooding is prohibited"
#define REASON_NFLOOD  "Nick flooding is prohibited"
#define REASON_JUPE    "Repeated attempts to join juped channels"
#define REASON_LINK    "Link looking is prohibited"
#define REASON_SPAM    "Spamming is prohibited"
#define REASON_CLONE   "Clones are prohibited"
#define REASON_RCLONE  "Reconnect clones"
#define REASON_SCLONE  "Clones on multiple servers"
#define REASON_DRONE   "Drones"

/* .kperm */
#define REASON_KPERM   "Permanent K-Line"

/*
 * E: lines in userlist.cf will overrule auto kills/klines
 * exemptions are also derived from /stats E /stats F
 * requests, unless the ircd tells tcm to use /stats I (hybrid 6 and higher)
 */

/* undef if you don't want glines reported */
#define REPORT_GLINES

/*
 * Define this to allow people with admin privileges on the tcm to
 * use .quote/.raw.  This is otherwise undocumented!
 * - The Hybrid team does not support the use of this option, and will
 *   take no responsibility for any damage it may cause.
 */
#define ENABLE_QUOTE

/* Define this to prevent tcm from forking() */
#undef DEBUGMODE

/* Define this for dmalloc malloc debugging package */
#undef DMALLOC

/* Maximum number of reconnections to a server allowed before quitting.  */
#define MAXRECONNECTS 5

/*
 * define this if you want services code at all
 */
#define SERVICES

/* to kline drones
 * drone detect only works if the tcm is global oper ;-(
 */

#define SERVICES_DRONES

/* whom to message for a global clone report */
#define SERVICES_NICK "services@services.xo"

/* name to expect services reply from */
#define SERVICES_NAME "services.xo"

/* EFnet will be moving SERVICES to services.int some
** time in the future.  It has (to my knowledge) passed
** voting, but has not yet been implemented.  When the
** time comes, you will have to remove the two define's
** above and uncomment these two.  -Hwy
**
** If you do not know what we're talking about, you don't
** need these options at all.
*/

/* #define SERVICES_NICK "services@services.int" */
/* #define SERVICES_NAME "services.int" */

/* how many clones to look for globally */
#define SERVICES_CLONE_THRESHOLD 4

/* how often to check for global clones in seconds */
#define SERVICES_CHECK_TIME 60

/* END OF SERVICES DEFINES */

/* Maximum connections;
 * XXX could make this FD_SETSIZE, but that might be a tad too large
 */
#define MAXDCCCONNS 1024

/* Define the low and high range of ports the tcm will try to use
 * when an oper issues PRIVMSG tcm .chat
 *
 * This allows an admin to open a specific range of ports to the tcm
 * for opers who are stuck behind NAT or strict firewalls they cannot
 * control.
 */
#define LOWEST_DCC_PORT 1025
#define HIGHEST_DCC_PORT 3050

/*
 * You can leave these, or change them to suit... - Dianora
 *
 * NICK_CHANGE_T1_TIME is the time in seconds, each nick that has
 * changed, will get decremented its nick change count, if the user
 * stops changing their nick.
 *
 * NICK_CHANGE_T2_TIME is how long in seconds, a nick will "live" until its
 * purged from the nick change table. Note, that it should be expired
 * by the NICK_CHANGE_T1_TIME eventually, but if a nick manages to make
 * a horrendous number of nick changes in a short time before being killed
 * or k-lined, this will ensure it gets purged within a reasonable length
 * of time (set to 5 minutes here)
 *
 * NICK_CHANGE_MAX_COUNT is the number of nick changes in a row allowed
 * without NICK_CHANGE_T1_TIME before a nick flood is reported.
 *
 * - Dianora
 */

#define NICK_CHANGE_T1_TIME  10
#define NICK_CHANGE_T2_TIME 300
#define NICK_CHANGE_MAX_COUNT 5

/* Parameters for detection of link lookers */
#define MAX_LINK_LOOKS 4
#define MAX_LINK_TIME 240

/* Parameters for detection of juped channel join flooders */
#define MAX_JUPE_JOINS 3
#define MAX_JUPE_TIME 60

/* Parameters for detection of connection flooders */
#define MAX_CONNECT_FAILS 4
#define MAX_CONNECT_TIME 20

/*
 * used in domain report
 * paragod reports 1000 for this, is too small on his servers
 * servers keep getting bigger. upped to 4k from 2k
 */

#define MAXDOMAINS     4000

/* Do not touch these unless you know what you are doing */
#define SPATH DPATH "/bin/tcm"

/* only needed if HAVE_REGEX_H is defined */
#define REGEX_SIZE 1024

/*
 * default ping timeout time from server
 * note: this value is only used if tcm cannot
 *       determine the ping-frequency value in
 *       the Y: lines.
 */
#define SERVER_TIME_OUT 300

/* default ping timeout when initially connecting to server */
#define SERVER_TIME_OUT_CONNECT 60

/* default DCC timeout */
#define DCC_TIMEOUT 30

/* XXX */
#define RECONNECT_CLONE_TABLE_SIZE 50

#endif
