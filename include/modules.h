#ifndef __MODULES_H_
#define __MODULES_H_

/* $Id: modules.h,v 1.14 2002/05/23 13:38:12 db Exp $ */

struct module {
  char *name;
  char *version;
  void *address;
};

struct common_function {
  int type;
  void (*function) (int connnum, int argc, char *argv[]);
  struct common_function *next;
};

struct common_function *signon;
struct common_function *signoff;
struct common_function *user_signon;
struct common_function *user_signoff;
struct common_function *dcc_signon;
struct common_function *dcc_signoff;
struct common_function *dcc;
struct common_function *upper_continuous;
struct common_function *continuous;
struct common_function *scontinuous;
struct common_function *config;
struct common_function *action;
struct common_function *reload;
struct common_function *wallops;
struct common_function *onjoin;
struct common_function *onctcp;
struct common_function *ontraceuser;
struct common_function *ontraceclass;
struct common_function *server_notice;
struct common_function *statsi;
struct common_function *statsk;
struct common_function *statse;
struct common_function *statso;

#define F_SIGNON		1
#define F_SIGNOFF		2
#define F_USER_SIGNON		3
#define F_USER_SIGNOFF		4
#define F_DCC_SIGNON		5
#define F_DCC_SIGNOFF		6
#define F_DCC			7
#define F_UPPER_CONTINUOUS	8
#define F_CONTINUOUS		9
#define F_SCONTINUOUS		10
#define F_CONFIG		11
/*				12 */
#define F_ACTION		13
#define F_RELOAD		14
#define F_WALLOPS		15
#define F_ONJOIN		16
#define F_ONCTCP		17
#define F_ONTRACEUSER		18
#define F_ONTRACECLASS		19
#define F_SERVER_NOTICE		20
#define F_STATSI		21
#define F_STATSK		22
#define F_STATSE		23
#define F_STATSO		24

extern void sendtoalldcc(int type,char *format,...);
extern void report(int type, int channel_send_flag, char *format,...);
extern char *date_stamp(void);

void m_modload(int connnum, int argc, char *argv[]);
void m_modunload(int connnum, int argc, char *argv[]);
void m_modreload(int connnum, int argc, char *argv[]);
void m_modlist(int connnum, int argc, char *argv[]);
void mod_add_cmd(struct TcmMessage *msg);
void mod_del_cmd(struct TcmMessage *msg);
void add_common_function(int type, void *function);
void modules_init(void);
int findmodule(char *name);
int load_all_modules(int logit);
int load_a_module(char *name, int logit);
int unload_a_module(char *name, int logit);

#endif
