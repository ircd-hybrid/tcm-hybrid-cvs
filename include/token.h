#ifndef __TOKEN_H
#define __TOKEN_H

/* tokens */

#define K_CLONES   	1
#define K_NFLOOD   	2
#define K_REHASH   	3
#define K_TRACE    	4
#define K_FAILURES 	5
#define K_DOMAINS  	6
#define K_BOTS     	8
#define K_NFIND    	9
#define K_LIST    	10
#define K_KILLLIST 	11
#define K_GLINE   	12
#define K_KLINE   	13
#define K_KCLONE  	14
#define K_KFLOOD  	15
#define K_KPERM   	16
#define K_KBOT    	17
#define K_KILL    	18
#define K_REGISTER 	19
#define K_OPERS   	20
#define K_TCMLIST 	21
#define K_TCMCONN 	22
#define K_ALLOW   	23
#define K_UMODE		24
#define K_CONNECTIONS 	25
#define K_DISCONNECT 	26
#define K_HELP    	27
#define K_CLOSE   	28
#define K_OP      	29
#define K_CYCLE   	30
#define K_DIE     	31
#define K_TCMINTRO   	32
#define K_DLINE		34
#define K_EXEMPTIONS	35
#define K_SET		36
#define K_UNKLINE	37
#define K_CLASS		38
#define K_CLASST	39
#define K_CHAT		40
#define K_SPAM		41
#define K_BAN		42
#define K_VBOTS		43
#define K_VLIST		44
#define K_KLINK		45
#define K_HMULTI	46
#define K_UMULTI	47
#define K_MEM		49
#define K_ACTION	50
#define K_MOTD		51
#define K_SAVE		52
#define K_LOAD		53
#define K_LOCOPS        54
#define K_INFO          55
#define K_KFIND         56
#define K_VMULTI	57
#define K_ULIST         58
#define K_HLIST         59
#define K_KDRONE	60
#define K_UPTIME        61
#define K_AUTOPILOT     62

char *splitc (char *rest, char divider);
char *split (char *first);
int occurance(char *string, char find);
int get_token(char *);	
void init_tokenizer();	

#endif
