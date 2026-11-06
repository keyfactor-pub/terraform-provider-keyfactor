#!/usr/bin/env perl
# parse-log.pl: offline analysis of one terraform demo run log -> JSON on stdout.
#
#   parse-log.pl [--allowlist FILE] LOGFILE
#
# Pure function of the log (no lab, no network, no env), so it can be tested
# against recorded logs: see harness/test.sh and harness/fixtures/. perl (core
# JSON::PP only) is used rather than jq because this is a line-oriented state
# machine (steps, error blocks, plan bodies); jq assembles/formats everything
# downstream.
#
# The log is whatever `make <demo>-lifecycle` printed. Structure is recovered
# from echoed make recipe lines (no makefile cooperation needed):
#   - "<...>/make [-C dir] <target> ..."   -> current PHASE (apply, plan,
#                                              import-all, drift-check, ...)
#   - "[unset ...;] TF_CLI_CONFIG_FILE=... terraform <cmd>" -> a new STEP
#   - "make[N]: *** [target] Error rc"      -> the failing chain; the failing
#                                              step is the step running when
#                                              the FIRST such line appears
#   - terraform's own "Plan:", "No changes.", "Apply complete!", error boxes
# ANSI colour is stripped, so old coloured logs and new -no-color logs parse
# identically. Error excerpts are secret-redacted (lib/Redact.pm) before they
# reach the JSON.
use strict;
use warnings;
use utf8;
use FindBin;
use lib "$FindBin::Bin/lib";
use JSON::PP;
use Redact qw(redact_line redact_text load_values);

my ($allowlist_file, $log);
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--allowlist') { $allowlist_file = shift @ARGV }
    elsif (!defined $log)       { $log = $a }
    else                        { die "unexpected argument: $a\n" }
}
die "usage: parse-log.pl [--allowlist FILE] LOGFILE\n" unless defined $log;
load_values($ENV{HARNESS_REDACT_VALUES_FILE});

my $MAX_DETAIL_LINES = 40;
my $MAX_LINE = 240;

# ---- allowlist --------------------------------------------------------------
# Line format:  <phase-glob> <address-glob> <attr>[,<attr>...]   # reason
# The reason is REQUIRED, and a rule whose three fields are all '*' is
# rejected: the allowlist exists to name specific expected write-only /
# perpetual-diff attributes, never to blanket-suppress drift. Only in-place
# updates can be allowlisted; create/destroy/replace is always drift.
my (@rules, @rejected);
if (defined $allowlist_file && -r $allowlist_file) {
    open my $af, '<', $allowlist_file or die "$allowlist_file: $!";
    my $ln = 0;
    while (my $l = <$af>) {
        $ln++;
        chomp $l;
        next if $l =~ /^\s*(?:#.*)?$/;
        my ($body, $reason) = split /\s+#\s*/, $l, 2;
        my @f = split ' ', $body;
        if (@f != 3 || !defined $reason || $reason !~ /\S/) {
            push @rejected, { line => $ln, why => 'need: <phase-glob> <address-glob> <attrs>  # reason' };
            next;
        }
        if ($f[0] eq '*' && $f[1] eq '*' && $f[2] eq '*') {
            push @rejected, { line => $ln, why => 'blanket "* * *" rule refused' };
            next;
        }
        push @rules, {
            phase  => _glob($f[0]),
            addr   => _glob($f[1]),
            attrs  => { map { $_ => 1 } split /,/, $f[2] },
            reason => $reason,
            src    => "$allowlist_file:$ln",
        };
    }
    close $af;
}
sub _glob { my $g = quotemeta shift; $g =~ s/\\\*/.*/g; return qr/^$g$/ }

# ---- parse ------------------------------------------------------------------
open my $fh, '<:encoding(UTF-8)', $log or die "$log: $!\n";

my $n = 0;
my ($phase, $marker) = ('', '');
my @steps;
my $cur;                       # current step
my ($in_cleanup) = (0);
my (@errors, %warn, @chain, @plain, @hfail);
my ($failed_idx, $failed_exit, $failed_line);
my ($skipped, $auth);
my %provider;
my $cleanup;
my ($block, $block_start);     # error box accumulator
my $cur_res;
my $in_warn_list = 0;

sub new_step {
    my ($cmd, $at) = @_;
    $cur->{line_end} = $at - 1 if $cur && !defined $cur->{line_end};
    $cur = {
        idx => scalar(@steps), cmd => $cmd, phase => $phase, marker => $marker,
        line_start => $at, cleanup => $in_cleanup ? JSON::PP::true : JSON::PP::false,
        plan => undef, applied => undef, changed => [], outside => 0,
        outputs_changed => JSON::PP::false, errors => 0, warnings => 0,
    };
    push @steps, $cur;
    $cur_res = undef;
}

while (my $line = <$fh>) {
    $n++;
    chomp $line;
    $line =~ s/\r$//;
    $line =~ s/\e\[[0-9;]*[A-Za-z]//g;

    # ---- inside a terraform error/warning box ----
    if (defined $block) {
        if ($line =~ /^\x{2575}/) {                       # ╵ closes the box
            finish_block($n);
            $block = undef;
        } else {
            my $t = $line;
            $t =~ s/^\x{2502} ?//;                        # strip leading │
            push @$block, $t;
        }
        next;
    }
    if ($line =~ /^\x{2577}/) {                           # ╷ opens a box
        $block = [];
        $block_start = $n;
        next;
    }

    # ---- echoed recipe lines (start in column 0) ----
    if ($line =~ /^\S/ && $line !~ /^if\b/ && $line !~ /^[A-Za-z]+:\s/ && $line !~ /^(?:Plan|No changes|Apply complete|Destroy complete)/) {
        if ($line =~ /^(?:set -a|unset|umask|cd |make |\S*\/make |[A-Za-z_]+=)/) {
            my $t;
            while ($line =~ /(?:^|[\s&;(])(?:\S*\/)?make(?:\s+-C\s+\S+)?\s+(?:-\S+\s+)*([A-Za-z][A-Za-z0-9_.-]*)(?=\s|;|$)/g) { $t = $1 }
            if (defined $t) {
                $phase = $t;
            }
            if ($line =~ /(?:^|[;&]\s*)TF_CLI_CONFIG_FILE=\S+\s+terraform\s+([a-z-]+)(?:\s+(rm|list|show|mv))?/ ||
                $line =~ /&&\s*TF_CLI_CONFIG_FILE=\S+\s+terraform\s+([a-z-]+)(?:\s+(rm|list|show|mv))?/) {
                my $cmd = $1;
                $cmd .= " $2" if defined $2 && $cmd eq 'state';
                new_step($cmd, $n);
                next;
            }
            if ($line =~ /^cd \S+ && (?:GOBIN=\S+ )?go install/) {
                new_step('build', $n);
                next;
            }
            next if defined $t;
        }
    }

    # continuation line of a multi-line echoed recipe, e.g. "  /usr/bin/make plan SUFFIX=_TF"
    if ($line =~ /^\s+(?:\S*\/)?make\s+(?:-C\s+\S+\s+)?([A-Za-z][A-Za-z0-9_.-]*)(?=\s|;|$)/) {
        $phase = $1;
        next;
    }
    # -compact-warnings renders warnings as a bullet list instead of a box:
    #   Warnings:\n\n- <summary>\n\nTo see the full warning notes, ...
    if ($line =~ /^Warnings:\s*$/) { $in_warn_list = 1; next }
    if ($in_warn_list) {
        if ($line =~ /^- (.+)$/) { $warn{ substr($1, 0, 100) }++; $cur->{warnings}++ if $cur; next }
        if ($line =~ /^\s*$/) { next }
        $in_warn_list = 0;
    }
    if ($line =~ /^==> Provider binary: (\S+) \(sha256 ([0-9a-f]+)\)/) {
        %provider = (path => $1, sha256 => $2);
        next;
    }
    if ($line =~ /^==> Provider installed to (\S+)/) {
        $provider{path} //= $1;
        next;
    }
    if ($line =~ /^==> (.*)/) {
        $marker = substr($1, 0, 100);
        next;
    }
    if ($line =~ /^HARNESS-CLEANUP-BEGIN/) { $in_cleanup = 1; next }
    if ($line =~ /^HARNESS-CLEANUP:\s*(.*)$/) {
        my (%kv, $rest);
        $rest = $1;
        while ($rest =~ /(\w+)=("[^"]*"|\S+)/g) { my ($k, $v) = ($1, $2); $v =~ s/^"|"$//g; $kv{$k} = $v }
        $cleanup = \%kv;
        next;
    }
    if ($line =~ /^SKIPPED:/) { $skipped //= redact_line(substr($line, 0, 200)); next }
    if ($line =~ /lab-env-check: stale OAuth secret/)  { $auth = 'stale_secret'; next }
    if ($line =~ /lab-env-check: token fetch failed/)  { $auth = 'token_fetch_failed'; next }
    if ($line =~ /^FAIL \(harness\)/) { push @hfail, redact_line(substr($line, 0, $MAX_LINE)) if @hfail < 10; next }

    if ($line =~ /^make(?:\[\d+\])?: \*\*\* \[([^\]]*)\] Error (\d+)/) {
        if ($in_cleanup) { next }
        push @chain, { line => $n, target => $1, rc => $2 + 0 };
        if (!defined $failed_idx) {
            $failed_idx  = $cur ? $cur->{idx} : undef;
            $failed_exit = $2 + 0;
            $failed_line = $n;
        }
        next;
    }

    next unless $cur;

    # ---- terraform output inside a step ----
    if ($line =~ /^Plan: (\d+) to add, (\d+) to change, (\d+) to destroy\./) {
        $cur->{plan} = { add => $1 + 0, change => $2 + 0, destroy => $3 + 0 };
        $cur_res = undef;
    } elsif ($line =~ /^No changes\./) {
        $cur->{plan} //= { add => 0, change => 0, destroy => 0 };
        $cur_res = undef;
    } elsif ($line =~ /^Changes to Outputs:/) {
        $cur->{outputs_changed} = JSON::PP::true;
        $cur_res = undef;
    } elsif ($line =~ /^Apply complete! Resources: (\d+) added, (\d+) changed, (\d+) destroyed/) {
        $cur->{applied} = { add => $1 + 0, change => $2 + 0, destroy => $3 + 0 };
    } elsif ($line =~ /^Destroy complete! Resources: (\d+) destroyed/) {
        $cur->{applied} = { add => 0, change => 0, destroy => $1 + 0 };
    } elsif ($line =~ /^  # (\S+) (will be created|will be updated in-place|will be destroyed|must be replaced|will be replaced|will be read during apply)\b/) {
        my %act = ('will be created' => 'create', 'will be updated in-place' => 'update',
                   'will be destroyed' => 'delete', 'must be replaced' => 'replace',
                   'will be replaced' => 'replace', 'will be read during apply' => 'read');
        $cur_res = { address => $1, action => $act{$2}, attrs => [] };
        push @{ $cur->{changed} }, $cur_res unless $cur_res->{action} eq 'read';
    } elsif ($line =~ /^  # (\S+) has changed\b/) {
        $cur->{outside}++;
        $cur_res = undef;
    } elsif ($cur_res && $line =~ /^      (?:[~+]|-\/\+|-) ([A-Za-z0-9_]+)\s*(?:=|\{)/) {
        my $a = $1;
        push @{ $cur_res->{attrs} }, $a unless grep { $_ eq $a } @{ $cur_res->{attrs} };
    } elsif ($line =~ /^(?:Error|ERROR|FAIL|FAILED)\b[:\s]/) {
        push @plain, redact_line(substr($line, 0, $MAX_LINE)) if @plain < 10;
    }
}
close $fh;
$cur->{line_end} = $n if $cur && !defined $cur->{line_end};
$_->{line_end} //= $n for @steps;

sub finish_block {
    my ($end) = @_;
    my @b = @$block;
    shift @b while @b && $b[0] !~ /\S/;
    my $first = shift @b;
    return unless defined $first;
    if ($first =~ /^Warning:\s*(.*)$/) {
        $warn{ substr($1, 0, 100) }++;
        $cur->{warnings}++ if $cur;
        return;
    }
    return unless $first =~ /^Error:\s*(.*)$/;
    my $summary = $1;
    my ($res, $at);
    for my $l (@b) {
        $res = $1 if !defined $res && $l =~ /^\s*with (\S+?),?\s*$/;
        $at  = "$1:$2" if !defined $at && $l =~ /^\s*on (\S+) line (\d+)/;
    }
    # redact the whole block (PEM bodies span lines), then clip long lines
    my @detail = map { length($_) > $MAX_LINE ? substr($_, 0, $MAX_LINE) . "..." : $_ } split(/\n/, redact_text(join("\n", @b)), -1);
    shift @detail while @detail && $detail[0] !~ /\S/;
    pop @detail while @detail && $detail[-1] !~ /\S/;
    my $truncated = @detail > $MAX_DETAIL_LINES;
    @detail = @detail[0 .. $MAX_DETAIL_LINES - 1] if $truncated;
    $cur->{errors}++ if $cur;
    push @errors, {
        step     => $cur ? $cur->{idx} : undef,
        phase    => $phase,
        cleanup  => $in_cleanup ? JSON::PP::true : JSON::PP::false,
        resource => $res,
        at       => $at,
        summary  => redact_line(substr($summary, 0, $MAX_LINE)),
        detail   => \@detail,
        truncated => $truncated ? JSON::PP::true : JSON::PP::false,
        log_line => $block_start,
        log_end  => $end,
    };
}

# ---- derive step results and drift -----------------------------------------
my ($plans_total, $plans_clean, $plans_changes) = (0, 0, 0);
my (@drift, @drift_allowed);
for my $s (@steps) {
    my $res;
    if (!$s->{cleanup} && ($s->{errors} || (defined $failed_idx && $s->{idx} == $failed_idx))) { $res = "error" }
    if ($s->{cmd} eq 'plan') {
        if (!$s->{cleanup}) {
            my $p = $s->{plan};
            my $changes = ($p && ($p->{add} || $p->{change} || $p->{destroy})) || @{ $s->{changed} } || $s->{outputs_changed};
            $res //= $changes ? "changes" : ($p ? "clean" : "unknown");
            $plans_total++;
            if ($res eq 'changes') {
                $plans_changes++;
                my @ch = @{ $s->{changed} };
                push @ch, { address => '(outputs)', action => 'outputs', attrs => [] } if $s->{outputs_changed} && !@ch;
                push @ch, { address => '(unparsed)', action => 'unknown', attrs => [] } if !@ch;
                my (@bad, @ok);
                for my $c (@ch) {
                    my $r = _allowed($s->{phase}, $c);
                    my %c = (%$c);
                    if ($r) { $c{allowlisted} = $r->{src}; $c{reason} = $r->{reason}; push @ok, \%c }
                    else    { push @bad, \%c }
                }
                push @drift, { step => $s->{idx}, phase => $s->{phase}, line => $s->{line_start},
                               plan => $s->{plan}, changes => [@bad, @ok] } if @bad;
                push @drift_allowed, { step => $s->{idx}, phase => $s->{phase}, line => $s->{line_start},
                                       changes => \@ok } if !@bad && @ok;
            } elsif ($res eq 'clean') { $plans_clean++ }
        }
    } elsif ($s->{cmd} eq 'apply') {
        $res //= $s->{applied} ? 'applied' : ($s->{plan} ? 'no-op' : 'ok');
    } elsif ($s->{cmd} eq 'destroy') {
        $res //= $s->{applied} ? 'destroyed' : 'ok';
    }
    $s->{result} = $res // 'ok';
    delete $s->{changed} unless @{ $s->{changed} };
}

sub _allowed {
    my ($ph, $c) = @_;
    return undef unless $c->{action} eq 'update' || $c->{action} eq 'outputs';
    return undef if $c->{action} eq 'update' && !@{ $c->{attrs} };
    for my $r (@rules) {
        next unless $ph =~ $r->{phase} && $c->{address} =~ $r->{addr};
        if ($c->{action} eq 'outputs') { return $r }
        my $all = 1;
        for my $a (@{ $c->{attrs} }) { $all = 0 unless $r->{attrs}{$a} || $r->{attrs}{'*'} }
        return $r if $all;
    }
    return undef;
}

my $failed;
if (defined $failed_idx || @chain) {
    my $s = defined $failed_idx ? $steps[$failed_idx] : undef;
    $failed = {
        step_index => $failed_idx,
        step       => $s ? $s->{cmd} : undef,
        phase      => $s ? $s->{phase} : undef,
        exit       => $failed_exit,
        lines      => $s ? [ $s->{line_start} + 0, $failed_line + 0 ] : [ $failed_line + 0, $failed_line + 0 ],
        chain      => \@chain,
    };
}

my %out = (
    log_lines     => $n,
    steps         => \@steps,
    plans         => { total => $plans_total, clean => $plans_clean, with_changes => $plans_changes },
    failed        => $failed,
    errors        => \@errors,
    warnings      => \%warn,
    plain_errors  => \@plain,
    harness_fail  => \@hfail,
    skipped       => $skipped,
    auth_preflight => $auth,
    provider      => \%provider,
    cleanup       => $cleanup,
    drift         => \@drift,
    drift_allowed => \@drift_allowed,
    allowlist     => { file => $allowlist_file, rules => scalar(@rules), rejected => \@rejected },
);
print JSON::PP->new->utf8->canonical->pretty->encode(\%out);
