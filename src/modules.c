/*
 * $Id: modules.c,v 1.40 2002/05/25 15:36:26 leeh Exp $B
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

#ifndef	RTLD_GLOBAL
#define	RTLD_GLOBAL RTLD_LAZY
#endif

const int max_mods = MODS_INCREMENT;
static const char unknown_ver[] = "<unknown>";
struct module modlist[MODS_INCREMENT];

static int hash_command(const char *);

struct dcc_command modload_msgtab = {
  "modload", NULL, {m_unregistered, m_not_admin, m_modload}
};
struct dcc_command modunload_msgtab = {
  "modunload", NULL, {m_unregistered, m_not_admin, m_modunload}
};
struct dcc_command modreload_msgtab = {
  "modreload", NULL, {m_unregistered, m_not_admin, m_modreload}
};
struct dcc_command modlist_msgtab = {
  "modlist", NULL, {m_unregistered, m_not_admin, m_modlist}
};

void modules_init(void)
{
  add_dcc_handler(&modload_msgtab);
  add_dcc_handler(&modunload_msgtab);
  add_dcc_handler(&modreload_msgtab);
  add_dcc_handler(&modlist_msgtab);
}

/* init_hashtables()
 *
 * input	-
 * output	-
 * side effects - clears the dcc command and server command hashtables
 */
void init_hashtables(void)
{
  memset(dcc_command_table, 0, sizeof(struct dcc_command) * MAX_HASH);
  memset(serv_command_table, 0, sizeof(struct serv_command) * MAX_HASH);
}

/* add_dcc_handler()
 *
 * input	- dcc command struct
 * output	-
 * side effects - command is added to dcc hash table
 */
void add_dcc_handler(struct dcc_command *ptr)
{
  int hashval;

  hashval = hash_command(ptr->cmd);

  if(dcc_command_table[hashval])
    ptr->next = dcc_command_table[hashval];
  
  dcc_command_table[hashval] = ptr;
}

/* del_dcc_handler()
 *
 * input	- dcc command
 * output	-
 * side effects - command (if found) is removed from dcc hashtable
 */
void del_dcc_handler(char *cmd)
{
  struct dcc_command *ptr;
  struct dcc_command *last_ptr = NULL;
  int hashval;
  
  hashval = hash_command(cmd);

  /* search the hash table for the command, we dont use 
   * find_dcc_handler because we need last_ptr
   */
  for(ptr = dcc_command_table[hashval]; ptr; ptr = ptr->next)
  {
    if(strcasecmp(cmd, ptr->cmd) == 0)
      break;

    last_ptr = ptr;
  }

  /* command was found.. */
  if(ptr)
  {
    /* something points to this command */
    if(last_ptr)
      last_ptr->next = ptr->next;
    
    /* this command is first in the hashtable */
    else
      dcc_command_table[hashval] = ptr->next;
  }
}

/* find_dcc_handler()
 *
 * input	- command
 * output	-
 * side effects - dcc handler is returned if found, else NULL
 */
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

/* hash_command()
 *
 * input	- command
 * output	-
 * side effects - command is changed into its hash value
 */
static int 
hash_command(const char *p)
{
  int hash_val = 0;

  while(*p)
  {
    hash_val += ((int)(*p)&0xDF);
    p++;
  }

  return(hash_val % MAX_HASH);
}

/* m_unregistered()
 *
 * sent to an oper who needs to register to use a command
 */
void
m_unregistered(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "You have not registered");
}

/* m_not_admin()
 *
 * sent to an oper who tries to execute an admin only command
 */
void
m_not_admin(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
		  "Only authorized admins may use this command");
}

int findmodule(char *name)
{
  int i;

  for (i=0; i < max_mods; ++i)
    if (!strcmp(modlist[i].name, name))
      return i;

  return -1;
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
