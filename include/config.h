#ifndef __CONFIG_H
#define __CONFIG_H

/*
 * tcm config.h
 * Global definitions obtained by including this file.
 */

/*
 * VIRTUAL, watch for clones from v hosted sites
 * only works on hybrid servers 5.1 and up
 */
#define VIRTUAL

/*
 * USE_CRYPT, define this is you want your oper passwords to be encrypted
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
 * If you are careful with your exemptions to D lines...
 */
#undef AUTO_DLINE

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
#define PREF_FILE "etc/tcm.pref"

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
#define HOW_TO_MAIL "/bin/mail -s"


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
for .kflood would be the #define for KLINE_REASON_KFLOOD etc. */

/* .kclone reason */
#define REASON_KCLONE "Clones are prohibited"

#define REASON_AUTO_MULTI_SERVER_CLONES "Clones on multiple servers"

/* .kflood reason */
#define REASON_KFLOOD "Flooding is prohibited"

/* ctcp flooders reason */
#define REASON_CTCP "Floodbot"

/* .kperm reason */
#define REASON_KPERM "PERMANENT"

/* .klink reason */
#define REASON_LINK   "Link lookers are prohibited"

/* .kspam reason */
#define REASON_KSPAM "Spamming is prohibited"

/* .kbot reason */
#define REASON_KBOT "Bots are prohibited"

/* .kdrone reason */
#define REASON_KDRONE "Drone bots"

/*
 * define this if you want services code at all
 */
#define SERVICES

/* to kline drones
 * drone detect only works if the tcm is global oper ;-(
 */

#define SERVICES_DRONES
#define REASON_DRONES "Auto-kline drones"

/*
 * E: lines in userlist.cf will overrule auto kills/klines
 * exemptions are also derived from /stats E /stats F
 * requests, unless the ircd tells tcm to use /stats I (hybrid 6)
 */

/* some dns spoofing detect code */

/*
 * If you have hybrid 5 or later, the IP is given on the +c
 * on the connect message.
 *
 * Note:  This should not be used on servers with a large user base,
 *	  because it will try to gethostbyname() every client you have.
 *	  This will lag your tcm considerably, and may even cause it to
 *	  ping timeout.
 *		-bill (proggy@earthling.net)
 */
#undef DETECT_DNS_SPOOFERS

/*
 * define this to flag wingates
 *
 * This must also be defined to detect SOCKS
 */
#define DETECT_WINGATE

/*
 * define this to flag open socks
 */
#define DETECT_SOCKS

/* undef if you don't want klines reported - Toast */
#define REPORT_KLINES

/*
 * define this if you trust remotely connected opers to
 * do klines on your tcm
 *
 * IF you define this, NONE of the remote .kline .kill .kbot .kclone
 * commands will work until they have .registered, i.e. you MUST have
 * a valid "O:user@host:opernick:password:ok" entry in userlist.cf
*/
#define REMOTE_KLINE

/*
 * If you don't want to allow registered opers on other tcm's
 * to do remote klines define this..
 * this (for now) disables the ability to do .kill @tcmnick user@host reason
*/
#undef RESTRICT_REMOTE_KLINE

/*
 * If you don't want to allow registered opers on other tcm's
 * to do remote dlines define this..
 */
#define RESTRICT_REMOTE_DLINE

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

/* Maximum linked tcm's allowed in tcm's tcmlist */
#define MAXTCMS 20

/* Maximum number of klines to keep record of */
#define MAXKLINES 5000

/* maximum number of hosts not to auto kline */
#define MAXHOSTS 100

/* maximum number of banned users on dcc connect,
   not used if OPERS_ONLY is defined */
#define MAXBANS 25

/* whom to message for a global clone report */
/* in the U.S. services */
#define SERVICES_NICK "services@services.us"

/* name to expect services reply from */
#define SERVICES_NAME "services.us"

/* how many clones to look for globally */
#define SERVICES_CLONE_THRESHOLD 4

/* how often to check for global clones */
#define SERVICES_CHECK_TIME 60

/* Maximum DCC chat connections */
#define MAXDCCCONNS 50

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
#define MAX_LINK_TIME 120

#define MAX_CONNECT_FAILS 4
#define MAX_CONNECT_TIME 20

/*
 * used in domain report
 * paragod reports 1000 for this, is too small on his servers
 * servers keep getting bigger. upped to 4k from 2k
 */

#define MAXDOMAINS     4000

/* remote tcm linking options */

/* This is the default TCM listen port if none is defined in tcm.cfg */
#define TCM_PORT 6800

/* How long to let a remote tcm attempt to connect, in seconds */
#define TCM_REMOTE_TIMEOUT 30

/* allow table size 
 * This table is used to .allow certain tcm nicks
 *  i.e. see the "spam" from those tcm's
 */
#define MAX_ALLOW_SIZE 20

#endif
