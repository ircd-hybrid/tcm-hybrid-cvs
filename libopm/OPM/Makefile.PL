use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

# $Id: Makefile.PL,v 1.1 2004/06/15 22:36:37 bill Exp $

WriteMakefile(
    'NAME'		=> 'OPM',
    'VERSION_FROM'	=> 'OPM.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'OPM.pm', # retrieve abstract from module
       AUTHOR     => 'David Leadbeater <dg@blitzed.org>') : ()),
    'LIBS'		=> ['-L../src/.libs -lopm'], # e.g., '-lm'
    'DEFINE'		=> '', # e.g., '-DHAVE_SOMETHING'
	# Insert -I. if you add *.h files later:
    'INC'		=> '', # e.g., '-I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # 'OBJECT'		=> '$(O_FILES)', # link all the C files too
);
