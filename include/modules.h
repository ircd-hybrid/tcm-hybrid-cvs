#ifndef __MODULES_H_
#define __MODULES_H_

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
struct common_function *continuous;
struct common_function *scontinuous;
struct common_function *config;
struct common_function *prefsave;
struct common_function *action;
struct common_function *reload;
struct common_function *wallops;
struct common_function *onjoin;
struct common_function *server_notice;

#define F_SIGNON	1
#define F_SIGNOFF	2
#define F_USER_SIGNON	3
#define F_USER_SIGNOFF	4
#define F_DCC_SIGNON	5
#define F_DCC_SIGNOFF	6
#define F_CONTINUOUS	7
#define F_SCONTINUOUS	8
#define F_CONFIG	9
#define F_PREFSAVE	10
#define F_ACTION	11
#define F_RELOAD	12
#define F_WALLOPS	13
#define F_ONJOIN	14
#define F_SERVER_NOTICE	15

extern void add_placed(char *file, int line);
extern void sendtoalldcc(int type,...);
extern void log_kline(char *command_name, char *pattern, int  kline_time, char *who_did_command,
                      char *reason);
extern void toserv(char *format, ... );
extern int okhost(char *user,char *host);
extern void report(int type, int channel_send_flag, char *format,...);
extern char *date_stamp(void);


void m_modload(int connnum, int argc, char *argv[]);
void m_modunload(int connnum, int argc, char *argv[]);
void m_modreload(int connnum, int argc, char *argv[]);
void m_modlist(int connnum, int argc, char *argv[]);

#endif
