/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  event.c: Event functions.
 *
 *  Copyright (C) 1998-2000 Regents of the University of California
 *  Copyright (C) 2001-2002 Hybrid Development Team
 *
 *  Code borrowed from the squid web cache by Adrian Chadd.
 *  Original header:
 *
 *  DEBUG: section 41   Event Processing
 *  AUTHOR: Henrik Nordstrom
 *
 *  SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 *  ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
 *
 *  $Id: event.c,v 1.11 2002/09/20 05:06:56 bill Exp $
 */

/*
 * How its used:
 *
 * Should be pretty self-explanatory. Events are added to the static
 * array event_table with a frequency time telling eventRun how often
 * to execute it.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

#include "tcm.h"
#include "event.h"
#include "stdcmds.h"
#include "tcm_io.h"
#include "userlist.h"

static const char *last_event_ran = NULL;
struct ev_entry event_table[MAX_EVENTS];
static time_t event_time_min = -1;


/*
 * void eventAdd(const char *name, EVH *func, void *arg, time_t when)
 *
 * Input: Name of event, function to call, arguments to pass, and frequency
 *	  of the event.
 * Output: None
 * Side Effects: Adds the event to the event list.
 */

void
eventAdd(const char *name, EVH *func, void *arg, time_t when)
{
  int i;
  
  /* find first inactive index, or use next index */
  for (i = 0; i < MAX_EVENTS; i++)
    if (event_table[i].active != YES)
      break;

  event_table[i].func = func;
  event_table[i].name = name;
  event_table[i].arg = arg;
  event_table[i].when = current_time + when;
  event_table[i].frequency = when; 
  event_table[i].active = YES;

  if ((event_table[i].when < event_time_min) || (event_time_min == -1))
    event_time_min = event_table[i].when;
}

/*
 * void eventDelete(EVH *func, void *arg)
 *
 * Input: Function handler, argument that was passed.
 * Output: None
 * Side Effects: Removes the event from the event list
 */

void
eventDelete(EVH *func, void *arg)
{
  int i;
 
  i = eventFind(func, arg);

  if (i == -1)
    return;
  
  event_table[i].name = NULL;
  event_table[i].func = NULL;
  event_table[i].arg = NULL;
  event_table[i].active = NO;
  event_table[i].when = 0;
  event_table[i].frequency = 0;
}

/* 
 * void eventAddIsh(const char *name, EVH *func, void *arg, time_t delta_isa)
 *
 * Input: Name of event, function to call, arguments to pass, and frequency
 *	  of the event.
 * Output: None
 * Side Effects: Adds the event to the event list within +- 1/3 of the
 *	         specified frequency.
 */
 
void
eventAddIsh(const char *name, EVH *func, void *arg, time_t delta_ish)
{
  if (delta_ish >= 3.0)
    {
      const time_t two_third = (2 * delta_ish) / 3;
      delta_ish = two_third + ((random() % 1000) * two_third) / 1000;
      /*
       * XXX I hate the above magic, I don't even know if its right.
       * Grr. -- adrian
       */
    }
  eventAdd(name, func, arg, delta_ish);
}

/*
 * void eventRun(void)
 *
 * Input: None
 * Output: None
 * Side Effects: Runs pending events in the event list
 */

void
eventRun(void)
{
  int i;

  for (i = 0; i < MAX_EVENTS; i++)
    {
      if ((event_table[i].active != YES) && (event_table[i].active != NO))
        {
          send_to_all(NULL, FLAGS_ADMIN, "*** Event table corruption: active is not YES or NO (func:0x%lx) (active:%d)",
                      event_table[i].func, event_table[i].active);
        }
      else if ((event_table[i].active == YES) && (event_table[i].when <= current_time))
        {
          last_event_ran = event_table[i].name;
          event_table[i].func(event_table[i].arg);
          event_table[i].when = current_time + event_table[i].frequency;
          event_time_min = -1;
        }
    }
}

/*
 * void eventInit(void)
 *
 * Input: None
 * Output: None
 * Side Effects: Initializes the event system. 
 */
void
eventInit(void)
{
  last_event_ran = NULL;
  memset(&event_table, 0, sizeof(struct ev_entry) * MAX_EVENTS);
}

/*
 * int eventFind(EVH *func, void *arg)
 *
 * Input: Event function and the argument passed to it
 * Output: Index to the entry in the event table
 * Side Effects: None
 */

int
eventFind(EVH *func, void *arg)
{
  int i;

  for (i = 0; i < MAX_EVENTS; i++)
    {
      if ((event_table[i].func == func) &&
          (event_table[i].arg == arg) &&
          (event_table[i].active == YES))
        return i;
    }
  return -1;
}

/* 
 * void show_events(struct connection *)
 *
 * Input: Client requesting the event
 * Output: List of events
 * Side Effects: None
 */

void
show_events(struct connection *connection_p)
{
  int i;

  if (last_event_ran)
    send_to_connection(connection_p,
		       "*** Last event to run: %s", last_event_ran);

  send_to_connection(connection_p, "*** Operation            Next Execution");

  for (i = 0; i < MAX_EVENTS; i++)
    {
      if (event_table[i].active == YES)
        {
          send_to_connection(connection_p,
		 "*** %-20s %-3d seconds",
		 event_table[i].name,
		 (int)(event_table[i].when - current_time));
        }
    }
  send_to_connection(connection_p, "*** Finished");
}

/* 
 * void set_back_events(time_t by)
 * Input: Time to set back events by.
 * Output: None.
 * Side-effects: Sets back all events by "by" seconds.
 */
void
set_back_events(time_t by)
{
  int i;

  for (i = 0; i < MAX_EVENTS; i++)
    if (event_table[i].when > by)
      event_table[i].when -= by;
    else
      event_table[i].when = 0;
}
