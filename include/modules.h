#ifndef __MODULES_H_
#define __MODULES_H_

/* $Id: modules.h,v 1.20 2002/05/24 20:52:40 leeh Exp $ */

struct module
{
  char *name;
  char *version;
  void *address;
};

extern void report(int type, int channel_send_flag, char *format,...);
extern char *date_stamp(void);

void m_modload(int connnum, int argc, char *argv[]);
void m_modunload(int connnum, int argc, char *argv[]);
void m_modreload(int connnum, int argc, char *argv[]);
void m_modlist(int connnum, int argc, char *argv[]);
void mod_add_cmd(struct TcmMessage *msg);
void mod_del_cmd(struct TcmMessage *msg);
void modules_init(void);
int findmodule(char *name);
int load_all_modules(int logit);
int load_a_module(char *name, int logit);
int unload_a_module(char *name, int logit);

#endif
