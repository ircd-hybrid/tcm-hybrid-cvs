#ifndef __NO_HANDLER_H
#define __NO_HANDLER_H

/* $Id: handler.h,v 1.2 2002/06/04 21:21:41 leeh Exp $ */

#define MAX_HASH 256

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
  struct serv_command *next;
  serv_handler handler;
};

struct serv_numeric
{
  struct serv_numeric *next;
  serv_numeric_handler handler;
};

void init_handlers(void);

void add_dcc_handler(struct dcc_command *);
void del_dcc_handler(struct dcc_command *);
struct dcc_command *find_dcc_handler(char *);

void add_serv_handler(struct serv_command *);
void del_serv_handler(struct serv_command *);
struct serv_command *find_serv_handler(char *);

void add_numeric_handler(struct serv_numeric *);
void del_numeric_handler(struct serv_numeric *);

#endif
