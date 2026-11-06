package Redact;
# Secret redaction for harness output. Shared by parse-log.pl (error excerpts
# that land in the summary JSON) and redact.pl (stdin->stdout filter used on
# everything run.sh prints). Conservative by design: it prefers over-redacting
# (e.g. a variable merely NAMED like a secret) to leaking.
#
# What it removes:
#   - PEM private-key blocks (multi-line, stateful in redact_text)
#   - "Authorization: Bearer ..." / "Bearer xyz" / "Basic xyz" credentials
#   - JWT-shaped strings (eyJ...)
#   - user:password@ in URLs
#   - the VALUE of any key whose name looks secret-like
#     (secret, password, passphrase, token, api_key, private_key, credential,
#      authorization, pfx, ...) in the forms  key = "v"  key=v  key: v
#     "key": "v"  and plan-diff  key = "old" -> "new"
#     (values like "(sensitive value)" / "(known after apply)" are left alone)
#   - literal secret VALUES loaded from a mode-600 values file
#     ($HARNESS_REDACT_VALUES_FILE, one value per line, min length 6),
#     which run.sh builds from the sourced KEYFACTOR_ENV_FILE
# What it does NOT do: entropy-based detection. A secret that is neither
# named like one nor present in the values file is not caught.
use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(redact_line redact_text load_values);

my $R = '[REDACTED]';

# key names that look secret-like; trailing url/uri/endpoint/path/file/id/name
# suffixes are NOT secrets (e.g. token_url, client_secret_file).
my $KEY = qr/[A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|passphrase|token|api[_-]?key|private[_-]?key|credential|authorization|pfx|keystore[_-]?pass)[A-Za-z0-9_.-]*/i;
my $SAFE_SUFFIX = qr/(?:url|uri|endpoint|path|file|id|name|ttl|timeout)$/i;

my @values;

sub load_values {
    my ($file) = @_;
    @values = ();
    return unless defined $file && -r $file;
    open my $fh, '<', $file or return;
    while (my $v = <$fh>) {
        chomp $v;
        push @values, $v if length($v) >= 6;
    }
    close $fh;
    # longest first so a value that contains another is replaced whole
    @values = sort { length($b) <=> length($a) } @values;
}

sub _keep_value {
    my ($v) = @_;
    return 1 if $v =~ /^\(/;                 # (sensitive value), (known after apply)
    return 1 if $v =~ /^\Q$R\E/;
    return 1 if $v =~ /^(?:null|true|false|""|''|\d{1,3})$/i;
    return 0;
}

sub redact_line {
    my ($s) = @_;
    return $s unless defined $s;

    $s =~ s/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/$1 $R/gi;
    $s =~ s/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/$R/g;
    $s =~ s{(://[^/\s:@"]+:)[^@\s/"]+@}{$1$R\@}g;

    # "key": "value"   (JSON, quoted key)
    $s =~ s/("($KEY)"\s*:\s*)"[^"]*"/_kv($&, $1, $2, "\"$R\"")/ge;
    # key = "old" -> "new"  |  key = "v"  |  key: "v"  |  key="v"
    $s =~ s/\b(($KEY)\s*[:=]\s*)"(?:[^"\\]|\\.)*"(?:\s*->\s*"(?:[^"\\]|\\.)*")?/_kv($&, $1, $2, $R)/ge;
    # key=v (unquoted; stops at whitespace, quote, & , ;)
    $s =~ s/\b(($KEY)\s*[:=]\s*)([^\s"&,;]+)/_kv_bare($1, $2, $3, $R)/ge;

    for my $v (@values) {
        $s =~ s/\Q$v\E/$R/g if index($s, $v) >= 0;
    }
    return $s;
}

sub _kv {
    my ($whole, $prefix, $key, $repl) = @_;
    return $whole if $key =~ $SAFE_SUFFIX;
    return $prefix . $repl;
}

sub _kv_bare {
    my ($prefix, $key, $val, $r) = @_;
    return $prefix . $val if $key =~ $SAFE_SUFFIX || _keep_value($val);
    return $prefix . $r;
}

sub redact_text {
    my ($text) = @_;
    my @out;
    my $in_pem = 0;
    for my $line (split /\n/, $text, -1) {
        if ($in_pem) {
            $in_pem = 0 if $line =~ /-----END [A-Z0-9 ]*PRIVATE KEY-----/;
            next;
        }
        if ($line =~ /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/) {
            push @out, '[REDACTED PRIVATE KEY BLOCK]';
            $in_pem = 1 unless $line =~ /-----END [A-Z0-9 ]*PRIVATE KEY-----/;
            next;
        }
        push @out, redact_line($line);
    }
    return join("\n", @out);
}

1;
