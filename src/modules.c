/*
 * much of this code has been copied (though none ver batum)
 * from ircd-hybrid-7.
 *
 * $Id: modules.c,v 1.23 2002/05/09 13:02:38 wcampbel Exp $B
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
#include "commands.h"
#include "modules.h"
#include "serverif.h"
#include "stdcmds.h"
#include "wild.h"

#define MODS_INCREMENT 25

#ifndef RTLD_NOW
#define RTLD_NOW RTLD_LAZY  /* apparantely openbsd has problems here */
#endif

const int max_mods = MODS_INCREMENT;
static const char unknown_ver[] = "<unknown>";
struct module modlist[MODS_INCREMENT];

extern struct connection connections[];

/*
 * I put this #ifdef here simply to show how I envision
 * implementing the loadable module support for insertion
 * directly into ircd-hybrid-7 in the future.
 */
#ifdef IRCD_HYBRID
/*
 * ircd-hybrid-7 loadable module code goes here.
 */
#else
struct TcmMessage modload_msgtab = {
 ".modload", 0, 1,
 {m_unregistered, m_not_oper, m_not_admin, m_modload}
};

struct TcmMessage modunload_msgtab = {
 ".modunload", 0, 1,
 {m_unregistered, m_not_oper, m_not_admin, m_modunload}
};

struct TcmMessage modreload_msgtab = {
 ".modreload", 0, 1,
 {m_unregistered, m_not_oper, m_not_admin, m_modreload}
};

struct TcmMessage modlist_msgtab = {
 ".modlist", 0, 1,
 {m_unregistered, m_not_oper, m_not_admin, m_modlist}
};
#endif

int findmodule(char *name)
{
  int i;
  for (i=0;i<max_mods;++i)
    if (!strcmp(modlist[i].name, name))
      return i;

  return -1;
}

#ifdef IRCD_HYBRID
/* code goes here later */
#else
void mod_add_cmd(struct TcmMessage *msg)
{
  int msgindex=0;

  assert(msg != NULL);
  while (msg_hash_table[msgindex].msg) ++msgindex;

  if ((msg_hash_table[msgindex].cmd = (char *)malloc(MAX_BUFF)) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in mod_add_cmd");
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

void add_common_function(int type, void *function)
{
  struct common_function **temp, *new;

  switch (type)
    {
      case F_SIGNON:
        temp = &signon;
        break;
      case F_SIGNOFF:
        temp = &signoff;
        break;
      case F_USER_SIGNON:
        temp = &user_signon;
        break;
      case F_USER_SIGNOFF:
        temp = &user_signoff;
        break;
      case F_DCC_SIGNON:
        temp = &dcc_signon;
        break;
      case F_DCC_SIGNOFF:
        temp = &dcc_signoff;
        break;
      case F_DCC:
        temp = &dcc;
        break;
      case F_UPPER_CONTINUOUS:
        temp = &upper_continuous;
        break;
      case F_CONTINUOUS:
        temp = &continuous;
        break;
      case F_SCONTINUOUS:
        temp = &scontinuous;
        break;
      case F_CONFIG:
        temp = &config;
        break;
      case F_ACTION:
        temp = &action;
        break;
      case F_RELOAD:
        temp = &reload;
        break;
      case F_WALLOPS:
        temp = &wallops;
        break;
      case F_ONJOIN:
        temp = &onjoin;
        break;
      case F_ONCTCP:
        temp = &onctcp;
        break;
      case F_ONTRACEUSER:
        temp = &ontraceuser;
        break;
      case F_ONTRACECLASS:
        temp = &ontraceclass;
        break;
      case F_SERVER_NOTICE:
        temp = &server_notice;
        break;
      case F_STATSI:
        temp = &statsi;
        break;
      case F_STATSK:
        temp = &statsk;
        break;
      case F_STATSE:
        temp = &statse;
        break;
      case F_STATSO:
        temp = &statso;
        break;
      default:
        return;
        break;
    }

  new = (struct common_function *) malloc(sizeof(struct common_function));
  new->type = type;
  new->function = function;
  new->next = (struct common_function *) NULL;
  while (*temp)
    temp = &(*temp)->next;
  *temp = new;
}

#endif

void modules_init(void)
{
  mod_add_cmd(&modload_msgtab);
  mod_add_cmd(&modunload_msgtab);
  mod_add_cmd(&modreload_msgtab);
  mod_add_cmd(&modlist_msgtab);

/*  if (signon == NULL)
    signon = (struct common_function *) malloc(sizeof(struct common_function));
  if (signoff == NULL)
    signoff = (struct common_function *) malloc(sizeof(struct common_function));
  if (dcc_signon == NULL)
    dcc_signon = (struct common_function *) malloc(sizeof(struct common_function));
  if (dcc_signoff == NULL)
    dcc_signoff = (struct common_function *) malloc(sizeof(struct common_function));
  if (dcc == NULL)
    dcc = (struct common_function *) malloc(sizeof(struct common_function));
  if (user_signon == NULL)
    user_signon = (struct common_function *) malloc(sizeof(struct common_function));
  if (user_signoff == NULL)
    user_signoff = (struct common_function *) malloc(sizeof(struct common_function));
  if (upper_continuous == NULL)
    upper_continuous = (struct common_function *) malloc(sizeof(struct common_function));
  if (continuous == NULL)
    continuous = (struct common_function *) malloc(sizeof(struct common_function));
  if (scontinuous == NULL)
    scontinuous = (struct common_function *) malloc(sizeof(struct common_function));
  if (config == NULL)
    config = (struct common_function *) malloc(sizeof(struct common_function));
  if (action == NULL)
    action = (struct common_function *) malloc(sizeof(struct common_function));
  if (reload == NULL)
    reload = (struct common_function *) malloc(sizeof(struct common_function));
  if (wallops == NULL)
    wallops = (struct common_function *) malloc(sizeof(struct common_function));
  if (onjoin == NULL)
    onjoin = (struct common_function *) malloc(sizeof(struct common_function));
  if (onctcp == NULL)
    onctcp = (struct common_function *) malloc(sizeof(struct common_function));
  if (ontraceuser == NULL)
    ontraceuser = (struct common_function *) malloc(sizeof(struct common_function));
  if (ontraceclass == NULL)
    ontraceclass = (struct common_function *) malloc(sizeof(struct common_function));
  if (server_notice == NULL)
    server_notice = (struct common_function *) malloc(sizeof(struct common_function));
  if (statsi == NULL)
    statsi = (struct common_function *) malloc(sizeof(struct common_function));
  if (statsk == NULL)
    statsk = (struct common_function *) malloc(sizeof(struct common_function));
  if (statse == NULL)
    statse = (struct common_function *) malloc(sizeof(struct common_function));
  if (statso == NULL)
    statso = (struct common_function *) malloc(sizeof(struct common_function));
*/
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
      sendtoalldcc(SEND_ADMIN_ONLY, "Error loading module %s: %s", name, err);
      return -1;
    }

  initmod = (void (*)(void)) dlsym(modpointer, "_modinit");
  if (initmod == NULL) initmod = (void (*)(void)) dlsym(modpointer, "__modinit");
  if (initmod == NULL)
    {
#ifdef DEBUGMODE
      printf("Module %s has no _modinit() function\n", name);
#endif
      sendtoalldcc(SEND_ADMIN_ONLY, "Module %s has no _modinit() function", name);
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
      sendtoalldcc(SEND_ALL_USERS, "Too many modules loaded\n");
      return -1;
    }
  modlist[i].address = modpointer;
  modlist[i].version = ver;
  if (!(modlist[i].name = (char *)malloc(30)))
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in load_a_module\n");
      exit(1);
    }
  strcpy(modlist[i].name, name);
  initmod();
  
  if (log)
    {
      sendtoalldcc(SEND_ADMIN_ONLY, "Module %s [version: %s] loaded at 0x%lx",
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
    sendtoalldcc(SEND_ADMIN_ONLY, "Module %s unloaded", name);
  return 0;
}

void m_modload (int connnum, int argc, char *argv[]) {
  if (argc != 2) return;
  if (load_a_module(argv[1], 1) != -1)
    sendtoalldcc(SEND_ADMIN_ONLY, "Loaded by %s", connections[connnum].nick);
  else
    prnt(connections[connnum].socket, "Load of %s failed\n", argv[1]);
}

void m_modunload (int connnum, int argc, char *argv[]) {
  if (argc != 2) return;
  if (unload_a_module(argv[1], 1) != -1)
    sendtoalldcc(SEND_ADMIN_ONLY, "Loaded by %s", connections[connnum].nick);
}

void m_modreload (int connnum, int argc, char *argv[]) {
  if (argc != 2) return;
  if (unload_a_module(argv[1], 0) != -1)
    {
      if (load_a_module(argv[1], 1))
        sendtoalldcc(SEND_ADMIN_ONLY, "Reloaded by %s", connections[connnum].nick);
    }
  else prnt(connections[connnum].socket, "Module %s is not loaded\n", argv[1]);
}

void m_modlist (int connnum, int argc, char *argv[]) {
  int i;

  if (argc >= 2)
    prnt(connections[connnum].socket, "Listing all modules matching '%s'...\n", argv[1]);
  else
    prnt(connections[connnum].socket, "Listing all modules...\n");
  for (i=0;i<max_mods;++i)
   {
     if (modlist[i].name != NULL)
       {
         if (argc == 2 && !wldcmp(argv[1], modlist[i].name))
           prnt(connections[connnum].socket, "--- %s 0x%lx %s\n", 
                modlist[i].name, modlist[i].address, modlist[i].version);
         else if (argc == 1)
           prnt(connections[connnum].socket, "--- %s 0x%lx %s\n", 
                modlist[i].name, modlist[i].address, modlist[i].version);
       }
   }
  prnt(connections[connnum].socket, "Done.\n");
}

/* XXX - Return value is ignored...use it or lose it... */
int load_all_modules(int log)
{
  DIR *module_dir;
  struct dirent *mdirent;
  char module_path[100];

  if (!(module_dir = opendir(MODULE_DIRECTORY)))
    {
      gracefuldie(0, __FILE__, __LINE__);
      return 0;
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
