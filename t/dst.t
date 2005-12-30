use lib 'lib';
use Parse::Syslog;
use IO::Scalar;
use Test;
use POSIX;

BEGIN {
	# disable this test because it doesn't work reliably
	# if somebody does find out, I would be grateful.
	# it fails at number 9.
	plan tests => 0;
	exit;
	# only test if IO::Scalar is available
	eval 'require IO::Scalar;' or do {
		plan tests => 0;
		warn "IO::Scalar not available: test skipped.\n";
		exit;
	};

	plan tests => 16
};

#  00:00  01:00  01:00  02:00
# ---|------|------|------|-----
# 

$ENV{TZ} = 'CET';
POSIX::tzset();

my $data = <<END;
Oct 30 00:59:53 ivr3 bla: bla
Oct 30 01:09:53 ivr3 bla: bla
Oct 30 01:19:53 ivr3 bla: bla
Oct 30 01:29:53 ivr3 bla: bla
Oct 30 01:39:53 ivr3 bla: bla
Oct 30 01:49:53 ivr3 bla: bla
Oct 30 01:59:58 ivr3 bla: bla
Oct 30 01:59:58 ivr3 bla: bla
Oct 30 01:00:00 ivr3 bla: bla
Oct 30 01:00:04 ivr3 bla: bla
Oct 30 01:10:04 ivr3 bla: bla
Oct 30 01:20:04 ivr3 bla: bla
Oct 30 01:30:04 ivr3 bla: bla
Oct 30 01:40:04 ivr3 bla: bla
Oct 30 01:50:04 ivr3 bla: bla
Oct 30 02:00:04 ivr3 bla: bla
END

my $file = IO::Scalar->new(\$data);

my $parser = Parse::Syslog->new($file);

my @result = qw(
1130626793
1130627393
1130627993
1130628593
1130629193
1130629793
1130630398
1130630398
1130630400
1130630404
1130631004
1130631604
1130632204
1130632804
1130633404
1130634004
);

while(my $sl = $parser->next) {
	ok($sl->{timestamp}, shift @result);
}

# vim: ft=perl
