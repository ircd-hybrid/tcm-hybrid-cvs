/* $Id: proxy.h,v 1.1 2004/06/15 22:36:31 bill Exp $ */

#ifndef __PROXY_H_
#define __PROXY_H_

#define DEFAULT_FDS 1024

#include "actions.h"
#include "libopm/src/opm.h"

unsigned int proxy_fds, proxy_timeout;
char proxy_vhost[MAX_IP+1];

int act_proxy;

struct scanner_conf
{
  char name[MAX_CONFIG+1];
  char target_ip[MAX_IP+1];
  char target_string[BUFFERSIZE];
  int target_port;

  OPM_T *scanner;

  dlink_list protocols;
  dlink_list targets;
};

struct protocol_conf
{
  int type;
  unsigned int port;
};

#define QUEUE_DCC		0x001	/* dcc user is manually checking a host	*/
#define QUEUE_CONNECTION	0x002	/* tcm is checking a connecting user	*/

struct scan_queue
{
  char ip[MAX_IP+1];
  unsigned int flags;

  struct scanner_conf *scanner_conf;
  struct user_entry *user;
  OPM_REMOTE_T *remote;

  struct connection *connection;
};

struct scanner_conf *scanner_create();
struct protocol_conf *protocol_create();
struct scan_queue *scan_queue_create();

void add_scanner(struct scanner_conf *);
void add_protocol_to_scanner(struct protocol_conf *, struct scanner_conf *);
void init_proxy_detection();

int enqueue_proxy_scan(struct scanner_conf *sc, char *ip, unsigned int flags, void *arg);

void dequeue_proxy_scan(OPM_T *, OPM_REMOTE_T *, int, void *);
void free_check(OPM_T *, OPM_REMOTE_T *, int, void *);
void proxy_scan_error(OPM_T *, OPM_REMOTE_T *, int, void *);

void cycle_scanners();
void logon_proxy_check(struct user_entry *);

#define HS_PROXY HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL
#define REASON_PROXY "Open proxy connections are prohibited"

#endif /* !__PROXY_H_ */
