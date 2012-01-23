#! /usr/bin/perl
#
# script to read spp_ipv6.h and print gen-msg.map lines for our SIDs

use strict;
use warnings "all";
use autodie;
use 5.12.0;

use Data::Dumper;
my $headerfile = "spp_ipv6_constants.h";
my $mapfile    = "gen-msg.map";
my $rulesfile  = "preprocessor.rules";
my $generator_id;
my %sidlines;

my $FH;
open $FH, "<", $headerfile;
while (<$FH>) {
	if (/^#define GEN_ID_IPv6\s+(\d+)/) {
		$generator_id = $1;
	} elsif ((/^#define (SID_\w+)\s+(\d+)/)
		|| (/^#define (SID_\w+_TEXT)\s+"(.*)"/)) {
		$sidlines{$1} = $2;
	}
}
close $FH;

my @out;
foreach my $item (reverse keys %sidlines) {
  push @out, [
	sprintf("%d", $generator_id),
	sprintf("%d", $sidlines{$item}),
	sprintf("%s", $sidlines{$item."_TEXT"}),
    sprintf("%s", $item)]
      unless ($item =~ /\w+_TEXT/);
}

open $FH, ">", $mapfile;
foreach my $line (sort  { @$a[1] <=> @$b[1] } @out) {
	say $FH join ' || ', @$line[0..2];
}
close $FH;

open $FH, ">", $rulesfile;
foreach my $line (sort  { @$a[1] <=> @$b[1] } @out) {
	say $FH 'alert ( msg: "'.@$line[3].'"; sid: '.@$line[1] .'; gid: '.@$line[0]
	  .'; rev: 1; metadata: rule-type preproc, classtype:bad-unknown; )';
}
close $FH;
