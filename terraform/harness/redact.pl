#!/usr/bin/env perl
# redact.pl: stdin -> stdout secret filter (see lib/Redact.pm for what it
# removes). Literal values to scrub can be supplied one per line in the file
# named by $HARNESS_REDACT_VALUES_FILE (mode 600; built by run.sh from the
# sourced env file; never printed).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Redact qw(redact_text load_values);

load_values($ENV{HARNESS_REDACT_VALUES_FILE});
local $/;
my $in = <STDIN>;
$in = '' unless defined $in;
my $out = redact_text($in);
print $out;
print "\n" if length($in) && substr($in, -1) eq "\n" && substr($out, -1) ne "\n";
