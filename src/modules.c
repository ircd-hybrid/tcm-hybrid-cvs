/*
 * much of this code has been copied (though none ver batum)
 * from ircd-hybrid-7.
 */

#include <assert.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "commands.h"
#include "tcm.h"
#include "modules.h"
#include "serverif.h"

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
#ifndef IRCD_MODULE
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

static int hash (char *p) {
  int hash_val;

  while (*p)
   {
     hash_val += ((int)(*p)&0xDF);
     p++;
   }

  return(hash_val % MAX_MSG_HASH);
}

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
void mod_add_cmd(struct TcmMessage *msg) {
  struct TcmMessageHash *ptr;
  struct TcmMessageHash *last_ptr;
  struct TcmMessageHash *new_ptr;
  int msgindex;

  assert(msg != NULL);
  msgindex = hash(msg->cmd);

  for (ptr = msg_hash_table[msgindex]; ptr; ptr = ptr->next)
    {
      if (!strcasecmp(msg->cmd, ptr->cmd)) return;
      last_ptr = ptr;
    }

  if ((new_ptr = (struct TcmMessageHash *)malloc(sizeof(struct TcmMessageHash))) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in mod_add_cmd");
      exit(1);
    }
  if ((new_ptr->cmd = (char *)malloc(MAX_BUFF)) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Ran out of memory in mod_add_cmd");
      exit(1);
    }

  new_ptr->next = NULL;
  strcpy(new_ptr->cmd, msg->cmd);
  new_ptr->msg = msg;

  if (last_ptr == NULL) msg_hash_table[msgindex] = new_ptr;
  else last_ptr->next = new_ptr;
}

void mod_del_cmd(struct TcmMessage *msg) {
  struct TcmMessageHash *ptr;
  struct TcmMessageHash *last_ptr;
  int msgindex;

  assert(msg != NULL);
  msgindex = hash(msg->cmd);

  for(ptr = msg_hash_table[msgindex]; ptr; ptr = ptr->next)
   {
     if (!strcasecmp(msg->cmd, ptr->cmd))
       {
         free(ptr->cmd);
         if (last_ptr != NULL)
           last_ptr->next = ptr->next;
         else
           msg_hash_table[msgindex] = ptr->next;
         free(ptr);
         return;
       }
     last_ptr = ptr;
   }
}

void add_common_function(int type, void *function)
{
  struct common_function *temp;

  switch (type)
    {
      case F_SIGNON:
        temp = signon;
        break;
      case F_SIGNOFF:
        temp = signoff;
        break;
      case F_USER_SIGNON:
        temp = user_signon;
        break;
      case F_USER_SIGNOFF:
        temp = user_signoff;
        break;
      case F_DCC_SIGNON:
        temp = dcc_signon;
        break;
      case F_DCC_SIGNOFF:
        temp = dcc_signoff;
        break;
      case F_DCC:
        temp = dcc;
        break;
      case F_UPPER_CONTINUOUS:
        temp = upper_continuous;
        break;
      case F_CONTINUOUS:
        temp = continuous;
        break;
      case F_SCONTINUOUS:
        temp = scontinuous;
        break;
      case F_CONFIG:
        temp = config;
        break;
      case F_PREFSAVE:
        temp = prefsave;
        break;
      case F_ACTION:
        temp = action;
        break;
      case F_RELOAD:
        temp = reload;
        break;
      case F_WALLOPS:
        temp = wallops;
        break;
      case F_ONJOIN:
        temp = onjoin;
        break;
      case F_ONCTCP:
        temp = onctcp;
        break;
      case F_ONTRACEUSER:
        temp = ontraceuser;
        break;
      case F_ONTRACECLASS:
        temp = ontraceclass;
        break;
      case F_SERVER_NOTICE:
        temp = server_notice;
        break;
      case F_STATSI:
        temp = statsi;
        break;
      case F_STATSK:
        temp = statsk;
        break;
      case F_STATSE:
        temp = statse;
        break;
      case F_STATSO:
        temp = statso;
        break;
      default:
        return;
        break;
    }

  if (!(temp && temp->function == NULL))
    {
      while (temp) temp=temp->next;
      temp = (struct common_function *) malloc(sizeof(struct common_function));
    }
  temp->type = type;
  temp->function = function;
  temp->next = (struct common_function *) NULL;
}

#endif

void modules_init(void) {
  mod_add_cmd(&modload_msgtab);
  mod_add_cmd(&modunload_msgtab);
  mod_add_cmd(&modreload_msgtab);
  mod_add_cmd(&modlist_msgtab);

  if (signon == NULL)
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
  if (prefsave == NULL)
    prefsave = (struct common_function *) malloc(sizeof(struct common_function));
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
}

int load_a_module(char *name, int log) {
  void *modpointer;
  char absolute_path[100], *ver, **verp;
  void (*initmod) (void);
  int i;
#ifdef DEBUGMODE
  placed;
#endif

  snprintf(absolute_path, sizeof(absolute_path), "%s/%s", get_current_dir_name(), name);
  if ((modpointer=dlopen(absolute_path, RTLD_NOW)) == NULL)
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
  modlist[i].name = (char *) dlsym(modpointer, "_name");

  if (modlist[i].name == NULL)
    modlist[i].name = (char *) dlsym(modpointer, "__name");
  if (modlist[i].name == NULL)
    modlist[i].name = (char *)&unknown_ver;
  initmod();
  
  if (log)
    {
      sendtoalldcc(SEND_ADMIN_ONLY, "Module %s [version: %s] loaded at 0x%lx",
                  (modlist[i].name == unknown_ver) ? name : modlist[i].name,
                   modlist[i].version, modlist[i].address);
#ifdef DEBUGMODE
      printf("Module %s [version: %s] loaded at 0x%lx\n",
            (modlist[i].name == unknown_ver) ? name : modlist[i].name,
             modlist[i].version, modlist[i].address);
#endif
    }
  return 0;
}

int unload_a_module(char *name, int log) {
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
  assert(argc == 1);
  if (load_a_module(argv[0], 1))
    sendtoalldcc(SEND_ADMIN_ONLY, "Loaded by %s", connections[connnum].nick);
}

void m_modunload (int connnum, int argc, char *argv[]) {
  assert(argc == 1);
  if (unload_a_module(argv[0], 1))
    sendtoalldcc(SEND_ADMIN_ONLY, "Loaded by %s", connections[connnum].nick);
}

void m_modreload (int connnum, int argc, char *argv[]) {
  assert(argc == 1);
  if (unload_a_module(argv[0], 0))
    {
      if (load_a_module(argv[0], 1))
        sendtoalldcc(SEND_ADMIN_ONLY, "Reloaded by %s", connections[connnum].nick);
    }
  else prnt(connections[connnum].socket, "Module %s is not loaded\n", argv[0]);
}

void m_modlist (int connnum, int argc, char *argv[]) {
  int i;
  assert (argc <= 1);
  if (argc == 1)
    prnt(connections[connnum].socket, "Listing all modules matching '%s'...\n", argv[0]);
  else
    prnt(connections[connnum].socket, "Listing all modules...\n");
  for (i=0;i<max_mods;++i)
   {
     if (argc == 1 && wldcmp(argv[0], modlist[i].name))
       prnt(connections[connnum].socket, "--- %s 0x%lx %s\n", 
            modlist[i].name, modlist[i].address, modlist[i].version);
     else if (!argc)
       prnt(connections[connnum].socket, "--- %s 0x%lx %s\n", 
            modlist[i].name, modlist[i].address, modlist[i].version);
   }
  prnt(connections[connnum].socket, "Done.\n");
}

int load_all_modules(int log)
{
  DIR *module_dir;
  struct dirent *mdirent;
  char module_path[100];

  if (!(module_dir = opendir(MODULE_DIRECTORY)))
    {
      gracefuldie(0, __FILE__, __LINE__);
      return;
    }
  while ((mdirent = readdir(module_dir)))
    {
      if (mdirent->d_name[strlen(mdirent->d_name) - 3] == '.' &&
          mdirent->d_name[strlen(mdirent->d_name) - 2] == 's' &&
          mdirent->d_name[strlen(mdirent->d_name) - 1] == 'o')
        {
          snprintf(module_path, sizeof(module_path), "%s%s", MODULE_DIRECTORY, 
                   mdirent->d_name);
          load_a_module(module_path, log);
        }
    }
   closedir(module_dir);
}
