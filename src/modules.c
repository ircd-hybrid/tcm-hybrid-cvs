/*
 * much of this code has been copied (though none verbatim)
 * from ircd-hybrid-7.
 *
 * $Id: modules.c,v 1.36 2002/05/25 02:16:51 leeh Exp $B
 *
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "commands.h"
#include "bothunt.h"
#include "modules.h"
#include "serverif.h"
#include "stdcmds.h"
#include "wild.h"
#include "parse.h"

#define MODS_INCREMENT 25

#ifndef RTLD_NOW
#define RTLD_NOW RTLD_LAZY  /* apparantely openbsd has problems here */
#endif

const int max_mods = MODS_INCREMENT;
static const char unknown_ver[] = "<unknown>";
struct module modlist[MODS_INCREMENT];

static int hash_command(const char *);

extern struct connection connections[];

void modules_init(void)
{
  add_dcc_handler("modload", m_unregistered, m_not_admin, m_modload);
  add_dcc_handler("modunload", m_unregistered, m_not_admin, m_modunload);
  add_dcc_handler("modreload", m_unregistered, m_not_admin, m_modreload);
  add_dcc_handler("modlist", m_unregistered, m_not_admin, m_modlist);
}

void init_hashtables(void)
{
  memset(dcc_command_table, 0, sizeof(struct dcc_command) * MAX_HASH);
  memset(serv_command_table, 0, sizeof(struct serv_command) * MAX_HASH);
}

void add_dcc_handler(char *cmd, void *oper_handler,
		     void *registered_oper_handler, void *admin_handler)
{
  struct dcc_command *ptr;
  int hashval;

  ptr = malloc(sizeof(struct dcc_command));
  memset(ptr, 0, sizeof(struct dcc_command));

  ptr->cmd = strdup(cmd);
  ptr->handler[0] = oper_handler,
  ptr->handler[1] = registered_oper_handler;
  ptr->handler[2] = admin_handler;
  
  hashval = hash_command(cmd);

  if(dcc_command_table[hashval])
    ptr->next = dcc_command_table[hashval];
  
  dcc_command_table[hashval] = ptr;
}

void del_dcc_handler(char *cmd)
{
  struct dcc_command *ptr;
  struct dcc_command *last_ptr = NULL;
  int hashval;
  
  hashval = hash_command(cmd);

  for(ptr = dcc_command_table[hashval]; ptr; ptr = ptr->next)
  {
    if(strcasecmp(cmd, ptr->cmd) == 0)
      break;

    last_ptr = ptr;
  }

  if(ptr)
  {
    if(last_ptr)
      last_ptr->next = ptr->next;
    else
      dcc_command_table[hashval] = ptr->next;

    free(ptr->cmd);
    free(ptr);
  }
}

struct dcc_command *
find_dcc_handler(char *cmd)
{
  struct dcc_command *ptr;
  int hashval;

  hashval = hash_command(cmd);

  for(ptr = dcc_command_table[hashval]; ptr; ptr = ptr->next)
  {
    if(strcasecmp(cmd, ptr->cmd) == 0)
      return ptr;
  }

  return NULL;
}

static int hash_command(const char *p)
{
  int hash_val = 0;

  while(*p)
  {
    hash_val += ((int)(*p)&0xDF);
    p++;
  }

  return(hash_val % MAX_HASH);
}
	
int findmodule(char *name)
{
  int i;

  for (i=0; i < max_mods; ++i)
    if (!strcmp(modlist[i].name, name))
      return i;

  return -1;
}

void mod_add_cmd(struct TcmMessage *msg)
{
  int msgindex=0;

  assert(msg != NULL);
  while (msg_hash_table[msgindex].msg) ++msgindex;

  if ((msg_hash_table[msgindex].cmd = (char *)malloc(MAX_BUFF)) == NULL)
    {
      send_to_all(SEND_ALL, "Ran out of memory in mod_add_cmd");
      exit(1);
    }

  strcpy(msg_hash_table[msgindex].cmd, msg->cmd);
  msg_hash_table[msgindex].msg = msg;
/*  msg_hash_table[msgindex].msg->handlers[3] = msg->handlers[3];
  msg_hash_table[msgindex].msg->handlers[2] = msg->handlers[2];
  msg_hash_table[msgindex].msg->handlers[1] = msg->handlers[1];
  msg_hash_table[msgindex].msg->handlers[0] = msg->handlers[0];*/
}

void mod_del_cmd(struct TcmMessage *msg)
{
  int msgindex=0;

  assert(msg != NULL);
  while (strcasecmp(msg_hash_table[msgindex].cmd, msg->cmd)) ++msgindex;
  free(msg_hash_table[msgindex].cmd);
  free(msg_hash_table[msgindex].msg);
}


int load_a_module(char *name, int log)
{
  void *modpointer;
  char absolute_path[100], *ver, **verp;
  void (*initmod) (void);
  int i;

  snprintf(absolute_path, sizeof(absolute_path), "%s/%s", getcwd((char *)NULL, 
           sizeof(absolute_path)-strlen(name)-1), name);
  if ((modpointer=dlopen(absolute_path, RTLD_NOW | RTLD_GLOBAL)) == NULL)
    {
      const char *err = dlerror();
#ifdef DEBUGMODE
      printf("Error loading module %s\n", err);
#endif
      send_to_all(SEND_ADMINS, "Error loading module %s: %s", name, err);
      return -1;
    }

  initmod = (void (*)(void)) dlsym(modpointer, "_modinit");
  if (initmod == NULL) initmod = (void (*)(void)) dlsym(modpointer, "__modinit");
  if (initmod == NULL)
    {
#ifdef DEBUGMODE
      printf("Module %s has no _modinit() function\n", name);
#endif
      send_to_all(SEND_ADMINS, "Module %s has no _modinit() function", name);
      dlclose(modpointer);
      return -1;
    }

  verp = (char **) dlsym(modpointer, "_version");
  if (verp == NULL) verp = (char **) dlsym(modpointer, "__version");
  if (verp == NULL) ver = (char *)&unknown_ver;
  else ver = *verp;
  
  for (i=0;i<max_mods;++i) if (!modlist[i].name) break;
  if (modlist[i].name)
    {
      send_to_all(SEND_ALL, "Too many modules loaded");
      return -1;
    }
  modlist[i].address = modpointer;
  modlist[i].version = ver;
  if (!(modlist[i].name = (char *)malloc(30)))
    {
      send_to_all(SEND_ALL, "Ran out of memory in load_a_module");
      exit(1);
    }
  strcpy(modlist[i].name, name);
  initmod();
  
  if (log)
    {
      send_to_all(SEND_ADMINS, "Module %s [version: %s] loaded at 0x%lx",
                  (modlist[i].name == unknown_ver) ? name : modlist[i].name,
                   modlist[i].version, (long)modlist[i].address);
#ifdef DEBUGMODE
      printf("Module %s [version: %s] loaded at 0x%lx\n",
            (modlist[i].name == unknown_ver) ? name : modlist[i].name,
             modlist[i].version, (long)modlist[i].address);
#endif
    }
  return 0;
}

int unload_a_module(char *name, int log)
{
  int modindex;
  void (*unloadmod) (void);

  if ((modindex = findmodule(name)) == -1)
    return -1;

  unloadmod = (void (*)(void)) dlsym(modlist[modindex].address, "_moddeinit");
  if (unloadmod == NULL)
    unloadmod = (void (*)(void)) dlsym(modlist[modindex].address, "__moddeinit");
  if (unloadmod != NULL)
    unloadmod();

  dlclose(modlist[modindex].address);
  modlist[modindex].name = NULL;
  modlist[modindex].version = NULL;
  modlist[modindex].address = NULL;

  if (log)
    send_to_all(SEND_ADMINS, "Module %s unloaded", name);
  return 0;
}

void m_modload (int connnum, int argc, char *argv[])
{
  if (argc != 2) return;
  if (load_a_module(argv[1], 1) != -1)
    send_to_all(SEND_ADMINS, "Loaded by %s", connections[connnum].nick);
  else
    print_to_socket(connections[connnum].socket, "Load of %s failed\n", argv[1]);
}

void m_modunload (int connnum, int argc, char *argv[])
{
  if (argc != 2) return;
  if (unload_a_module(argv[1], 1) != -1)
    send_to_all(SEND_ADMINS, "Loaded by %s", connections[connnum].nick);
}

void m_modreload (int connnum, int argc, char *argv[])
{
  if (argc != 2) return;
  if (unload_a_module(argv[1], 0) != -1)
    {
      if (load_a_module(argv[1], 1))
        send_to_all(SEND_ADMINS, "Reloaded by %s", connections[connnum].nick);
    }
  else
    print_to_socket(connections[connnum].socket,
		    "Module %s is not loaded", argv[1]);
}

void m_modlist (int connnum, int argc, char *argv[])
{
  int i;

  if (argc >= 2)
    print_to_socket(connections[connnum].socket,
		    "Listing all modules matching '%s'...", argv[1]);
  else
    print_to_socket(connections[connnum].socket, "Listing all modules...");

  for (i=0;i<max_mods;++i)
   {
     if (modlist[i].name != NULL)
       {
         if (argc == 2 && !wldcmp(argv[1], modlist[i].name))
           print_to_socket(connections[connnum].socket, "--- %s 0x%lx %s", 
                modlist[i].name, modlist[i].address, modlist[i].version);
         else if (argc == 1)
           print_to_socket(connections[connnum].socket, "--- %s 0x%lx %s", 
                modlist[i].name, modlist[i].address, modlist[i].version);
       }
   }
  print_to_socket(connections[connnum].socket, "Done.");
}

/* XXX - Return value is ignored...use it or lose it... */
int load_all_modules(int log)
{
  DIR *module_dir;
  struct dirent *mdirent;
  char module_path[100];

  if (!(module_dir = opendir(MODULE_DIRECTORY)))
    {
      /* XXX some sort of more useful error would be nice here */
      exit(-1);
    }
  while ((mdirent = readdir(module_dir)))
    {
      if (strlen(mdirent->d_name) > 3 &&
          mdirent->d_name[0] != '.' &&
          mdirent->d_name[strlen(mdirent->d_name) - 3] == '.' &&
          mdirent->d_name[strlen(mdirent->d_name) - 2] == 's' &&
          mdirent->d_name[strlen(mdirent->d_name) - 1] == 'o')
        {
          snprintf(module_path, sizeof(module_path), "%s%s", MODULE_DIRECTORY, 
                   mdirent->d_name);
          load_a_module(module_path, log);
        }
    }
   closedir(module_dir);
   return 1;
}
