#! /usr/bin/env perl

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# This file removes every lfence line that has a comment saying "load_only"
# in the assembly scripts provided by Intel for control flow LVI mitigation.

use strict;
use warnings;

my $file = $ARGV[0];

open(my $fh, "<", $file) or die "Could not open file '$file' $!";
my @lines = <$fh>;
close $fh;

open($fh, ">", $file) or die "Could not open file '$file' $!";
foreach my $line (@lines) {
    print $fh $line unless $line =~ /load_only/;
}
close $fh;
