This is a VERY brief intro to the TexasNet Connection Monitoring Bot.

I. What it does

  Its main function is to identify people who abuse the local server
  in general.  It identifies potential clonebotters (more than 3
  connections from a host in 15 seconds), potential bot-runners (more
  than 1 active connection from the same userhost), potential infinitely
  reconnecting bots (counts the number of rejected connections from a
  given userhost due to K-lines, server full, etc.), and counts the
  number of connections from each domain on the server.  It does NOT
  hold a channel, give out ops, kill or kick people, or join/part
  channels on request.

  Clonebot detection is done proactively (i.e. it notifies any opers
  of clonebots as they are detected).  The other functions listed
  above are tracked, but only reported when asked for.

II. What it needs

  This bot requires two (possibly 3 things):

    1. A server which reports Client connects/disconnects to opers.
       Any of the latest +CS or digi versions of the server have
       this feature.  In order to use the "failures" feature, you
       will also need to have reporting of failed connections available.
       This is done by default on +CS servers, and can be turned on in
       the config.h in digi servers.

    2. Either a global or local O-line on the server.  In order to
       get the info mentioned on #1, the bot has to be opered, despite
       how much I hate opered bots.

    3. If you choose to give the bot only a local O-line, you will
       either have to patch the server code to allow local opers to
       see invisible users on a /trace, or you will have some 
       reporting discrepancies for users who are already on the
       server when you run the bot.  I reccomend patching the server
       code.  It's a one line fix to s_serv.c under m_trace().  See
       Section IV below for the patch.

III. How to use it

  Unzip it, untar it, read this file. :)  Then edit the config.h file,
  changing whatever you need to or feel like.  Edit the Makefile to
  uncomment the operating system you are using.  Edit userlist.load
  to show which userhosts will be recognized as opers to the bot.
  (Opers have access to many more commands than normal users)

  Finally, edit bothunt.c and fill in the #defines for the OLINENICK
  and OLINEPASSWD.  Then you can "make" the bot.  Once it compiles
  into the executable "tcm", you can run it.  Note that it dumps a
  log of ALL input/output it gets to stdout, so your best move is
  to run the bot as "tcm > /dev/null &".  You may also redirect stdout
  to a file to maintain a complete (but HUGE) log of everything the
  bot sees/does.

  Once the bot is running, it is controlled via DCC CHAT.  If you
  open a DCC CHAT connection to the bot, it will announce you and
  tell you about the help command.  Play around with any of the
  commands you want... only "massversion" is not implemented.

  If you have a DCC CHAT to the bot open, it will automatically send
  you reports of possible clonebot connections and notices of any
  other users/opers connecting/disconnecting from the monitor bot.
  The bot also announces all potential clonebots (as they connect)
  to the channel it is on.  This channel defaults to "&monitor".

IV.  Patching your server code to allow bot to have a local O-line

  This fix is VERY simple, and IMHO should be made to the server
  distribution package.  Its effect is to let local opers see invisible
  users when doing /trace.  I see know reason why they should not be
  allowed to get a list of all users on their server via /trace.
  Anyway, follow the following directions to make this patch:

  Go into the ircd subdirectory of your server distribution and edit
  the file "s_serv.c".
  Locate the line which reads: "!(MyConnect(sptr) && IsOper(sptr)) &&"
  Modify this line to read:    "!(MyConnect(sptr) && IsAnOper(sptr)) &&"

  That's it.  The only difference is "IsOper" vs. "IsAnOper",  Now just
  rebuild the server and you're on the way.

If you have problems/questions, feel free to e-mail me at jimi@texas.net

Chris -=- Hendrix on IRC
jimi@texas.net
