/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  event.h: The ircd event header.
 *
 *  Copyright (C) 2002 by the past and present ircd coders, and others.
 *
 *  The original never had a GPL REMOVED with pleasure -db
 *
 *  $Id: event.h,v 1.2 2002/06/24 00:40:15 db Exp $
 */

#ifndef __EVENT_H__
#define __EVENT_H__

struct connection;

/*
 * How many event entries we need to allocate at a time in the block
 * allocator. 16 should be plenty at a time.
 */
#define	MAX_EVENTS	50


typedef void EVH(void *);

/* The list of event processes */
struct ev_entry
{
  EVH *func;
  void *arg;
  const char *name;
  time_t frequency;
  time_t when;
  struct ev_entry *next;
  int active;
};

extern void eventAdd(const char *name, EVH *func, void *arg, time_t when);
extern void eventAddIsh(const char *name, EVH *func, void *arg, time_t delta_ish);
extern void eventRun(void);
extern time_t eventNextTime(void);
extern void eventInit(void);
extern void eventDelete(EVH *func, void *);
extern int eventFind(EVH *func, void *);
extern void set_back_events(time_t);

extern void show_events(struct connection *);

#endif
