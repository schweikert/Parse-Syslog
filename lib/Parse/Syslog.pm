package Parse::Syslog;

use Carp;
use Symbol;
use Time::Local;
use strict;
use vars qw($VERSION);

$VERSION = '0.03';

my %months_map = (
    'Jan' => 0, 'Feb' => 1, 'Mar' => 2,
    'Apr' => 3, 'May' => 4, 'Jun' => 5,
    'Jul' => 6, 'Aug' => 7, 'Sep' => 8,
    'Oct' => 9, 'Nov' =>10, 'Dec' =>11
);

sub new($$;%)
{
    my ($class, $file, %data) = @_;
    croak "new() requires one argument: file" unless defined $file;
    %data = () unless %data;
    if(not defined $data{year}) {
        $data{year} = (localtime(time))[5]+1900;
    }
    $data{_repeat}=0;

    if(ref $file eq 'File::Tail') {
        $data{filetail} = 1;
        $data{file} = $file;
    }
    else {
        $data{file}=gensym;
        open($data{file}, "<$file") or croak "can't open $file: $!";
    }

    return bless \%data, $class;
}

sub _next_line($)
{
    my $self = shift;
    my $f = $self->{file};
    if(defined $self->{filetail}) {
        return $f->read;
    }
    else {
        return <$f>;
    }
}

sub next($)
{
    my ($self) = @_;

    while($self->{_repeat}>0) {
        $self->{_repeat}--;
        return $self->{_last_data};
    }

    line: while(my $str = $self->_next_line()) {
        # date, time and host 
        $str =~ /^
            (\w{3})\s+(\d+)   # date  -- 1, 2
            \s
            (\d+):(\d+):(\d+) # time  -- 3, 4, 5
            \s
            ([-\w\.]+)        # host  -- 6
            \s+
            (.*)              # text  -- 7
            $/x or do
        {
            carp "line not in syslog format: $str";
            next line;
        };
        
        my $mon = $months_map{$1};
        defined $mon or croak "unknown month $1\n";

        # year change
        $self->{year}++ if defined $self->{_last_mon}
            and $self->{_last_mon} > $mon;
        $self->{_last_mon} = $mon;

        # convert to unix time
        my $time;
        if($self->{GMT}) {
            $time = timegm($5,$4,$3,$2,$mon,$self->{year}-1900);
        }
        else {
            $time = timelocal($5,$4,$3,$2,$mon,$self->{year}-1900);
        }

        my ($host, $text) = ($6, $7);
        
        # last message repeated ... times
        if($text =~ /^last message repeated (\d+) time/) {
            next line if defined $self->{repeat} and not $self->{repeat};
            next line if not defined $self->{_last_data};
            $1 > 0 or do {
                carp "last message repeated 0 or less times??";
                next line;
            };
            $self->{_repeat}=$1-1;
            return $self->{_last_data};
        }

        # some systems send over the network their
        # hostname prefixed to the text. strip that.
        $text =~ s/^[-\w+\.]+\s+//;

        # snort log
        $text =~ /^
            (\S+?)          # program   -- 1
            (?:\[(\d+)\])?  # PID       -- 2
            :\s+
            (?:\[ID\ (\d+)\ ([a-z0-9]+)\.([a-z]+)\]\ )?   # Solaris 8 "message id" -- 3, 4, 5
            (.*)            # text      -- 6
            $/x or do
        {
            carp "line not in syslog format: $str";
            next line;
        };

        $self->{_last_data} = {
            timestamp => $time,
            host      => $host,
            program   => $1,
            pid       => $2,
            msgid     => $3,
            facility  => $4,
            level     => $5,
            text      => $6,
        };

        return $self->{_last_data};
    }
    return undef;
}

1;

__END__

=head1 NAME

Parse::Syslog - Parse Unix syslog files

=head1 SYNOPSIS

 my $parser = Parse::Syslog->new('/var/log/syslog', year=>2001);
 while(my $sl = $parser->next) {
     ... access $sl->{timestamp|host|program|pid|text} ...
 }

=head1 DESCRIPTION

Unix syslogs are convenient to read for humans but because of small differences
between operating systems and things like 'last message repeated xx times' not
very easy to parse by a script.

Parse::Syslog presents a simple interface to parse syslog files: you create
a parser on a file (with B<new>) and call B<next> to get one line at a time
with Unix-timestamp, host, program, pid and text returned in a hash-reference.

=head1 Constructing a Parser

B<new> requires as first argument a file-name for the syslog-file to be parsed.
Alternatively, you can pass a File::Tail object as first argument, in which
case the I<read> method will be called to get lines to process.

After the file-name (or File::Tail object), you can specify options as a hash.
The following options are defined:

=over 8

=item B<year>

Syslog files usually do store the time of the event without year. With this
option you can specify the start-year of this log. If not specified, it will be
set to the current year.

=item B<GMT>

If this option is set, the time in the syslog will be converted assuming it is
GMT time instead of local time.

=item B<repeat>

Parse::Syslog will by default repeat xx times events that are followed by
messages like 'last message repeated xx times'. If you set this option to
false, it won't do that.

=back

=head1 Parsing the file

The file is parse one line at a time by calling the B<next> method, which returns
a hash-reference containing the following keys:

=over 10

=item B<timestamp>

Unix timestamp for the event.

=item B<host>

Host-name where the event did happen.

=item B<program>

Program-name of the program that generated the event.

=item B<pid>

PID of the Program that generated the event. This information
is not always available for every operating system.

=item B<text>

Text description of the event.

=item B<msgid>

Message numeric identifier, available only on Solaris >= 8 with "message ID
generation" enabled".

=item B<facility>

Log facility name, available only on Solaris >= 8 with "message ID
generation" enabled".

=item B<level>

Log level, available only on Solaris >= 8 with "message ID
generation" enabled".

=back

=head1 BUGS

There are many small differences in the syslog syntax between operating
systems. This module has been tested for syslog files produced by the following
operating systems:

    Debian GNU/Linux 2.4 (sid)
    Solaris 2.6
    Solaris 8

Report problems for these and other operating systems to the author.

=head1 COPYRIGHT

Copyright (c) 2001, Swiss Federal Institute of Technology, Zurich.
All Rights Reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

David Schweikert <dws@ee.ethz.ch>

=cut

# vi: sw=4 et
