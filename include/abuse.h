#ifndef __ABUSE_H
#define __ABUSE_H

extern void do_a_kline(char *command_name,
		       int kline_time,
		       char *pattern,
		       char *reason,
		       char *who_did_command);

void suggest_kill_kline(int reason,
			char* nick,char* user,char* host,
			int different, int identd);

char* format_reason(char *reason);



/* types for suggest_kline() */

#define R_CLONES	0x001
#define R_VCLONES       0x002
#define R_SCLONES	0x004
#define R_FLOOD		0x008
#define R_LINK		0x010
#define R_BOTS		0x020
#define R_WINGATE	0x040
#define R_SOCKS		0x080
#define R_CTCP		0x100
#define R_SPOOF		0x200
#define R_SPAMBOT	0x400

#endif
