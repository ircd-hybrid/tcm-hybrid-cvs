#ifndef __MODULES_H_
#define __MODULES_H_

/* $Id: modules.h,v 1.19 2002/05/24 18:19:24 leeh Exp $ */

struct module
{
  char *name;
  char *version;
  void *address;
};

struct common_function
{
  int type;
  void (*function) (int connnum, int argc, char *argv[]);
  struct common_function *next;
};

struct common_function *user_signon;
struct common_function *user_signoff;
struct common_function *dcc;
struct common_function *upper_continuous;
struct common_function *continuous;
struct common_function *scontinuous;
struct common_function *config;
struct common_function *reload;

#define F_USER_SIGNON		3
#define F_USER_SIGNOFF		4
#define F_DCC			7
#define F_UPPER_CONTINUOUS	8
#define F_CONTINUOUS		9
#define F_SCONTINUOUS		10
#define F_CONFIG		11
#define F_RELOAD		14

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
