#ifndef __MODULES_H_
#define __MODULES_H_

/* $Id: modules.h,v 1.29 2002/06/24 00:40:15 db Exp $ */

struct connection;

#define MAX_HASH 256

struct module
{
  char name[30];
  char *version;
  void *address;
};

void m_unregistered(struct connection *, int argc, char *argv[]);
void m_not_admin(struct connection *, int argc, char *argv[]);
extern int load_all_modules(int log);
void m_modload(struct connection *, int argc, char *argv[]);
void m_modunload(struct connection *, int argc, char *argv[]);
void m_modreload(struct connection *, int argc, char *argv[]);
void m_modlist(struct connection *, int argc, char *argv[]);
void modules_init(void);
int findmodule(char *name);
int load_all_modules(int logit);
int load_a_module(char *name, int logit);
int unload_a_module(char *name, int logit);

#endif
