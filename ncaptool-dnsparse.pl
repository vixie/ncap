#! /usr/bin/perl

# $Id$

#
# Copyright (c) 2007-2008 by Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use warnings;
use strict;

# [368 dg 127.0.0.1/7433] 2007-10-24 02:33:54.070973000 [00000000 00000000] \
#         [203.73.24.8].53 [204.152.187.1].52572 \
#         dns QUERY,NOERROR,22562,qr \
#         1 bm.nsysu.edu.tw,IN,MX 0 \
#         7 edu.tw,IN,NS,86400,moevax.edu.tw \
#         edu.tw,IN,NS,86400,moemoon.edu.tw \
#         edu.tw,IN,NS,86400,moestar.edu.tw \
#         edu.tw,IN,NS,86400,a.twnic.net.tw \
#         edu.tw,IN,NS,86400,b.twnic.net.tw \
#         edu.tw,IN,NS,86400,c.twnic.net.tw \
#         edu.tw,IN,NS,86400,d.twnic.net.tw \
#         10 a.twnic.net.tw,IN,A,86400,192.83.166.9 \
#         a.twnic.net.tw,IN,AAAA,86400,2001:288:1:1002:2e0:18ff:fe77:f174 \
#         b.twnic.net.tw,IN,A,86400,192.72.81.200 \
#         c.twnic.net.tw,IN,A,86400,168.95.192.10 \
#         d.twnic.net.tw,IN,A,86400,210.17.9.229 \
#         d.twnic.net.tw,IN,AAAA,86400,2001:c50:ffff:1:2e0:18ff:fe95:b22f \
#         moevax.edu.tw,IN,A,86400,140.111.1.2 \
#         moemoon.edu.tw,IN,A,86400,192.83.166.17 \
#         moemoon.edu.tw,IN,AAAA,86400,2001:288:1:1002::a611 \
#         moestar.edu.tw,IN,A,86400,163.28.6.21

my $line = '';
while (<>) {
	chomp;
	$line .= $_;
	if ($line =~ /\\$/o) {
		chop $line;
		next;
	}
	$_ = $line;
	$line = '';
	my $ref = { };
	next unless /^\[(\d+)[^\]]*\]\s+([\d\-]+)\s+([\d\:\.]+)\s+/;
	@$ref{'len', 'date', 'time'} = ($1, $2, $3);
	$_ = $';
	next unless /^\[([[:xdigit:]]+)\s+([[:xdigit:]]+)\]\s+/;
	@$ref{'user1', 'user2'} = ($1, $2);
	$_ = $';
	next unless /^\[([[:xdigit:]\.\:]+)\]\.(\d+)\s+/;
	@$ref{'saddr', 'sport'} = ($1, $2);
	$_ = $';
	next unless /^\[([[:xdigit:]\.\:]+)\]\.(\d+)\s+/;
	@$ref{'daddr', 'dport'} = ($1, $2);
	$_ = $';
	my ($word, @words) = split;

	if ($word eq 'dns') {
		&dns($ref, \@words);
	}
}
exit 0;

sub dns {
	my ($ref, $w) = @_;

	my ($opcode, $rcode, $id, $flags) = split /,/, shift @$w;
	$flags = '' unless defined $flags;
	my %flags = ( );
	foreach (split /\|/, $flags) {
		$flags{$_} = '';
	}

	my $question = &dns_sect($w);
	return unless $#$question == $[;
	$question = @$question[$[];

	my $answer = &dns_sect($w);
	my $authority = &dns_sect($w);
	my $additional = &dns_sect($w);

	printf "%s %s %s %s %s %s %d %s %s %s\n",
		@$ref{'date', 'time', 'saddr', 'daddr'},
		$opcode, $rcode, $id,
		@$question{'name', 'class', 'type'};
	foreach my $sect ($answer, $authority, $additional) {
		foreach my $rr (@$sect) {
			printf "\t%s %s %s %d %s\n",
				@$rr{'name', 'class', 'type', 'ttl', 'rdata'};
		}
	}
}

sub dns_sect {
	my $w = shift;
	my @ret = ( );

	for (my $count = shift @$w; $count > 0; $count--) {
		my %rr = ( );
		@rr{'name', 'class', 'type', 'ttl', 'rdata'} =
			split /,/, shift @$w;
		next if defined $rr{rdata} && $rr{rdata} =~ /^\[/o;
		push @ret, \%rr;
	}
	return \@ret;
}

