#ifndef __CONFIG_H
#define __CONFIG_H

/*
 * tcm config.h
 * Global definitions obtained by including this file.
 *
 * $Id: config.h,v 1.52 2002/05/25 16:49:15 wcampbel Exp $
 */

/*
 * VIRTUAL, watch for clones from v hosted sites
 * only works on hybrid servers 5.1 and up
 */
#define VIRTUAL

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
 * lagged.org use something called "Calvin" for auto expiring of k-lines.
 * if you want support for this, define the following.
 */
#undef CALVIN

/*
 *  If you don't like the idea of any remote oper including those on the
 * tcm, being able to D line, define this
 */
#undef NO_D_LINE_SUPPORT

/*
 * The default tcm config file , can be overridden with a file name
 *  argument to tcm
 */

#define MODULE_DIRECTORY "modules/"

#define CONFIG_FILE "etc/tcm.cf"
#define USERLIST_FILE "etc/userlist.cf"

#define HELP_PATH "help"        /* No / at the end */
#define HELP_FILE "help"        /* Inside of HELP_PATH */
#define MOTD_FILE "etc/motd.txt"

#define LOGFILE "logs/tcm.log"
#define LAST_LOG_NAME "logs/last_log_name"

/* Where nasty errors are logged */
#define ERROR_LOG "logs/error.log"

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
#define REASON_LINK    "Link looking is prohibited"
#define REASON_BOT     "Bots are prohibited"
#define REASON_SPAMBOT "Spamming is prohibited"
#define REASON_CLONE   "Clones are prohibited"
#define REASON_RCLONE  "Reconnect clones"
#define REASON_SCLONE  "Clones on multiple servers"
#define REASON_DRONE   "Drones"
#define REASON_SOCKS   "Open SOCKS Proxy"
#define REASON_WINGATE "Open WinGate Proxy"
#define REASON_SQUID   "Open Squid Proxy"

/* .kperm */
#define REASON_KPERM   "Permanent K-Line"

/*
 * E: lines in userlist.cf will overrule auto kills/klines
 * exemptions are also derived from /stats E /stats F
 * requests, unless the ircd tells tcm to use /stats I (hybrid 6 and higher)
 */

/*
 * define this to flag wingates
 */
#define DETECT_WINGATE

/*
 * define this to flag open socks
 */
#define DETECT_SOCKS

/*
 * define this to flag open Squid proxies
 */
#define DETECT_SQUID

/*
 * define the ip and port you want a Socks 4 test to connect back to.
 * Suggest using the relevant irc servers ip for a proper check.
 * Do not use hostnames here.
 *
 * YOU MUST CHANGE THIS TO SOMETHING REAL.  You can setup a listen in inetd
 * if you'd like; it does not nessicarily have to connect to an ircd.
 *
 * Note: This same port and IP will be used in Squid detection, if defined.
 */
#define SOCKS_CHECKPORT 6667
#define SOCKS_CHECKIP "127.0.0.1"

/*
 * define this to the string to use to determine if a Squid is open or not
 * note: this is potentially inaccurate, if the server you are connecting
 * to is running an irc server on the port you are checking for a Squid proxy.
 * note2: csircd does not send this notice, for whatever reason, so you must
 * use something else.  newer versions of Squid will send a message:
 * "Connection Established" when they succesfully connect to their target.
 */
#define SQUID_STRING "Looking up your hostname"

/* undef if you don't want klines reported - Toast */
#define REPORT_KLINES

/* Define this to enable the +W flag, which is required for a tcm oper
 * to be able to see OPERWALL/WALLOPS, LOCOPS is provided by the l
 * user flag.
 */
#undef ENABLE_W_FLAG

/*
 * Define this to allow people with admin privileges on the tcm to
 * use .quote/.raw.  This is otherwise undocumented!
 * - The Hybrid team does not support the use of this option, and will
 *   take no responsibility for any damage it may cause.
 */
#undef ENABLE_QUOTE

/* Define this to prevent tcm from forking() */
#undef DEBUGMODE

/* Define this for dmalloc malloc debugging package */
#undef DMALLOC

/* Maximum number of reconnections to a server allowed before quitting.  */
#define MAXRECONNECTS 5

/* Maximum users allowed in tcm userlist */
#define MAXUSERS 100

/* maximum number of hosts not to auto kline */
#define MAXHOSTS 100

/* max users of glines to support */
#define MAXBANS 25

/*
 * define this if you want services code at all
 */
#undef SERVICES

/* to kline drones
 * drone detect only works if the tcm is global oper ;-(
 */

#define SERVICES_DRONES
#define REASON_DRONES "Auto-kline drones"

/* whom to message for a global clone report */
#define SERVICES_NICK "services@services.us"

/* name to expect services reply from */
#define SERVICES_NAME "services.us"

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

/* Maximum DCC chat connections */
#define MAXDCCCONNS 50

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

/* 
 *  change if you wish - Dianora
 *
 * Link looker parameters
 *
 * Allow a user MAX_LINK_LOOKS link looks within 
 * MAX_LINK_TIME seconds
 *
 * With links pacing, MAX_LINK_TIME has to go up
 *
 */
#define MAX_LINK_LOOKS  4
#define MAX_LINK_TIME 240

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
#endif
