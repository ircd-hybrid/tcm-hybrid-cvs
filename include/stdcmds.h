#ifndef __STDCMDS_H
#define __STDCMDS_H

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void who(char *nick);
void whois(char *nick);
void names(char *chan);
void join(char *chan,char *key);
void leave(char *chan);
void notice(char *nick,...);
void privmsg(char *nick,...);
void say(char *chan,...);
void action(char *chan,char *msg);
void newnick(char *nick);
void invite(char *nick,char *chan);

#endif
