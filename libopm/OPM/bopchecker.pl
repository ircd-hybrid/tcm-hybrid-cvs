#!/usr/bin/perl
# A basic open proxy checker based on libopm and the OPM perl module
# Reads a file on stdin and returns if the proxies are open

# Basic protocol: (>> sent to bopchecker, << recived from bopchker).
# >> ip.ad.re.ss
# << ip.ad.re.ss open port,portN protocol,protocolN 
# << ip.ad.re.ss closed
# << ip.ad.re.ss error string
#
# You can also specify additional ports and protocols to test:
#  >> ip.ad.re.ss [default] [port_list] [protocol_list]
# Or use UNKNOWN as a protocol to try every protocol on that port:
#  >> ip.ad.re.ss [port] UNKNOWN
#
# Examples:
#
# Test all the default ports/protocols on 1.2.3.4
# >> 1.2.3.4 default
#
# Test only HTTP CONNECT on port 5678 of host 1.2.3.4
# >> 1.2.3.4 5678 HTTP
#
# Test all default ports/protocols, plus every protocol on port 5678
# >> 1.2.3.4 default 5678 UNKNOWN

# $Id: bopchecker.pl,v 1.1 2004/06/15 22:36:38 bill Exp $

use strict;
use IO::Select;
use OPM;

$SIG{PIPE} = 'IGNORE';

# Buffer of input from STDIN
my $buffer;
# Temp. storage of ports proxies are open on
my %open;
# Number of open proxies found
my $numopen;

my $select = new IO::Select ( \*STDIN );

my $scan = OPM->new or die("Error loading OPM");

sub add_default {
   my $remote = shift;
   my $home = $ENV{'HOME'};

# Take protocols from $HOME/.bopcheckerrc in format:
# protocols = HTTP:80,81,3128 SOCKS4:1080,1182
# and so on
   if (-f "$home/.bopcheckerrc") {
      my $cfg = "$home/.bopcheckerrc";
      open(CFG, "< $cfg") or die "Can't open $cfg for reading: $!";
#      print STDERR "Reading protocols/ports from $cfg...\n";

      while(<CFG>) {
         next if (/^#/);

         if(/^\s*protocols\s*=\s*(.*)$/i) {
            my $protos_ports = $1;
            $protos_ports =~ s/^\s*//g;
            foreach my $proto_ports (split(/\s+/, $protos_ports)) {
               if($proto_ports =~ /^([A-Z0-9]+):([0-9,]+)$/i) {
                  my $proto = $1;
                  my $ports = $2;

                  unless(OPM::constant("TYPE_$proto", 0)) {
                     print STDERR "Unknown protocol type $proto in $cfg: $proto_ports\n";
                  }

                  foreach my $port (split(/,/, $ports)) {
                     $remote->addtype(OPM::constant("TYPE_$proto", 0), $port);
#                     print STDERR "Added $proto:$port\n";
                  }
               } else {
                  print STDERR "Broken protocol/ports in $cfg: $proto_ports\n";
                  exit;
               }
            }
         }
      }

      close(CFG);
      return;
   }

   for(80, 81, 2282, 3128, 3332, 3382, 3777, 3802, 4044, 4480, 5490, 6588, 6682, 8000, 8080, 8081, 8090, 22788, 28178, 46214, 48316, 57123, 65506) {
       $remote->addtype(OPM->TYPE_HTTP, $_);
   }
   
   for(80, 81, 808, 1075, 1182, 2282, 3128, 3382, 4480, 6588, 8000, 8080, 8081, 8090, 46213, 53201) {
       $remote->addtype(OPM->TYPE_HTTPPOST, $_);
   }
   
   for(81, 889, 1027, 1028, 1029, 1066, 1075, 1080, 1180, 1478, 2280, 2425, 3330, 3380, 4044, 4455, 4777, 4894, 4914, 5748, 6000, 6042, 6826, 7198, 7366, 7441, 8799, 9036, 9938, 10000, 10001, 14728, 15859, 17878, 22799, 26859, 30021, 30022, 32343, 34167, 38994, 40934, 41934, 43934, 53201, 53311, 53412, 57123) {
       $remote->addtype(OPM->TYPE_SOCKS4, $_);
   }

# These seem to be even more common than port 1080, at least on IRCnet :(
   for(81, 1080, 1813, 1978, 2280, 4438, 5104, 5113, 5262, 5634, 6552, 6561, 7464, 7810, 8130, 8148, 8175, 8520, 8814, 9100, 9186, 9447, 9578, 17879, 25791) {
       $remote->addtype(OPM->TYPE_SOCKS5, $_);
   }

   $remote->addtype(OPM->TYPE_ROUTER, 23);

   for(23, 1181) {
       $remote->addtype(OPM->TYPE_WINGATE, $_);
   }
}

# local interface to bind to
$scan->config(OPM->CONFIG_BIND_IP, "82.195.234.3");
$scan->config(OPM->CONFIG_FD_LIMIT, 1024);
$scan->config(OPM->CONFIG_MAX_READ, 512);

# XXX: make configurable           "quorn.blitzed.org"
$scan->config(OPM->CONFIG_SCAN_IP, "82.195.234.3");
$scan->config(OPM->CONFIG_SCAN_PORT, 16667);
$scan->config(OPM->CONFIG_TARGET_STRING, "proxy check k thx");

$scan->callback(OPM->CALLBACK_END, \&callback_end);
$scan->callback(OPM->CALLBACK_OPENPROXY, \&callback_openproxy);

MAIN: while(1) {
   for my $sock($select->can_read(0.5)) {
      my $tmp;
      if(sysread($sock, $tmp, 1024) == 0) {
         last MAIN;
      }
      $buffer .= $tmp;

      while($buffer =~ s/^([^\n]+)\n//) {
         my($remote, $proxy, $proxyip);
         $proxy = $1;

         ($proxyip) = $proxy =~ /^([^ ]+)/;
         $remote = OPM->new($proxyip);
         
         if($proxy !~ / / or $proxy =~ s/ default//) {
            add_default($remote);
         }

         if($proxy =~ / (.+) (.+)$/) {
            my @ports = split ',', $1;
            my @types = split ',', $2;

            for(0 .. $#ports) {
# Make protocol 'UNKNOWN' be a shortcut for all protocols.
               if ($types[$_] eq 'UNKNOWN') {
                   my $p = $_;
                   for('HTTP','HTTPPOST','SOCKS4','SOCKS5','ROUTER','WINGATE') {
                       $remote->addtype(OPM::constant("TYPE_$_", 0), $p);
                   }
                   next;
               }

               unless(OPM::constant("TYPE_$types[$_]", 0)) {
                  print "$proxyip error Unknown protocol type ($types[$_])\n";
                  next;
               }
               $remote->addtype(
                     OPM::constant("TYPE_$types[$_]", 0), $ports[$_]);
            }
	 }

         my $error = $scan->scan($remote);
         if($$error != OPM->SUCCESS) {
            print "$proxyip error " . $error->string . "\n";
         }
      }
   }
   $scan->cycle;
}

while($scan->active) {
#   sleep 1;
   select(undef, undef, undef, 0.25);
   $scan->cycle;
}

exit $numopen;


sub callback_openproxy {
   my($scan, $remote, $val) = @_;
   push @{$open{$remote->ip}}, [$remote->port, $remote->protocol];
}

sub callback_end {
   my($scan, $remote, $val) = @_;
   my $ip = $remote->ip;

   if(exists $open{$ip}) {
      printf("%s open %s %s\n", $ip,
         join(",", map { $_->[0] } @{$open{$ip}}),
         join(",", map { $_->[1] } @{$open{$ip}}));
      delete $open{$ip};
      $numopen++;
   }else{
      print "$ip closed\n";
   }

   $remote->free;
}

