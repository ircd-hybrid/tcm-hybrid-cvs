#ifndef __MODULES_H_
#define __MODULES_H_

/* $Id: modules.h,v 1.26 2002/05/25 22:25:07 leeh Exp $ */

#define MAX_HASH 256

struct module
{
  char name[30];
  char *version;
  void *address;
};

struct dcc_command *dcc_command_table[MAX_HASH];
struct serv_command *serv_command_table[MAX_HASH];
struct serv_numeric *serv_numeric_table;

typedef void (*dcc_handler)(int connnum, int argc, char *argv[]);
typedef void (*serv_handler)(int argc, char *argv[]);
typedef void (*serv_numeric_handler)(int numeric, int argc, char *argv[]);

struct dcc_command
{
  char *cmd;
  struct dcc_command *next;
  dcc_handler handler[3];
};

struct serv_command
{
  char *cmd;
  struct serv_command *next_cmd;
  struct serv_command *next_func;
  serv_handler handler;
};

struct serv_numeric
{
  struct serv_numeric *next;
  serv_numeric_handler handler;
};

void add_dcc_handler(struct dcc_command *);
void del_dcc_handler(struct dcc_command *);
struct dcc_command *find_dcc_handler(char *);

void add_serv_handler(struct serv_command *);
void del_serv_handler(struct serv_command *);
struct serv_command *find_serv_handler(char *);

void add_numeric_handler(struct serv_numeric *);
void del_numeric_handler(struct serv_numeric *);

void m_unregistered(int connnum, int argc, char *argv[]);
void m_not_admin(int connnum, int argc, char *argv[]);

extern void report(int type, int channel_send_flag, char *format,...);
extern char *date_stamp(void);

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
