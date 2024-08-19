use Test;
use POSIX;
use lib "lib";
BEGIN { plan tests => 41 };
use Parse::Syslog;
ok(1); # If we made it this far, we're ok.

#########################
$ENV{TZ} = 'CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00';
POSIX::tzset();

my $parser = Parse::Syslog->new("t/linux-rfc3339syslog");
open(PARSED, "<t/linux-parsed") or die "can't open t/linux-parsed: $!\n";
while(my $sl = $parser->next) {
        my $is = '';
        $is .= "time    : ".(gmtime($sl->{timestamp}))."\n";
        $is .= "host    : $sl->{host}\n";
        $is .= "program : $sl->{program}\n";
        $is .= "pid     : ".(defined $sl->{pid} ? $sl->{pid} : 'undef')."\n";
        $is .= "text    : $sl->{text}\n";
        $is .= "\n";
        print "$is";

        my $shouldbe = '';
        $shouldbe .= <PARSED>;
        $shouldbe .= <PARSED>;
        $shouldbe .= <PARSED>;
        $shouldbe .= <PARSED>;
        $shouldbe .= <PARSED>;
        $shouldbe .= <PARSED>;

        ok($is, $shouldbe);
}

# vim: set filetype=perl:
