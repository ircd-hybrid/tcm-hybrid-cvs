#ifndef __MODULES_H_
#define __MODULES_H_

/* $Id: modules.h,v 1.28 2002/05/28 12:14:13 leeh Exp $ */

#define MAX_HASH 256

struct module
{
  char name[30];
  char *version;
  void *address;
};

void m_unregistered(int connnum, int argc, char *argv[]);
void m_not_admin(int connnum, int argc, char *argv[]);
extern int load_all_modules(int log);
void m_modload(int connnum, int argc, char *argv[]);
void m_modunload(int connnum, int argc, char *argv[]);
void m_modreload(int connnum, int argc, char *argv[]);
void m_modlist(int connnum, int argc, char *argv[]);
void modules_init(void);
int findmodule(char *name);
int load_all_modules(int logit);
int load_a_module(char *name, int logit);
int unload_a_module(char *name, int logit);

#endif
