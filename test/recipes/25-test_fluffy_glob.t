#!/sw/perl/bin/perl
#
# Fluffy: wildcard (glob) lookups for -CApath/-CAfile/-CRLfile,
# SSL_CERT_FILE/SSL_CERT_DIR, X509_load_crl_file() and the default config
# file, exercised against a CA/leaf/CRL fixture laid out like late-bound
# /sw/<pkg>/etc/ssl trees under the test's own result directory.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Copy;
use File::Path qw(make_path);
use File::Spec::Functions qw(catdir rel2abs);
use OpenSSL::Test qw/:DEFAULT/;

setup("test_fluffy_glob");

plan skip_all => "glob(3) lookups are Unix only"
    if $^O eq 'MSWin32' || $^O eq 'VMS';

plan tests => 15;

my $td = rel2abs("fx");

sub ossl { return run(app(["openssl", @_])); }

sub spew {
    my ($f, $s) = @_;
    open(my $fh, '>', $f) or die "$f: $!";
    print $fh $s;
    close($fh) or die "$f: $!";
}

sub hash_of {
    my ($cert) = @_;
    my @l = run(app(["openssl", "x509", "-hash", "-noout", "-in", $cert]),
                capture => 1);
    chomp(my $h = $l[0] // '');
    return $h;
}

my @ca_ext = ("-addext", "basicConstraints=critical,CA:TRUE",
              "-addext", "keyUsage=critical,keyCertSign,cRLSign");

sub fixture {
    make_path(map { "$td/$_" }
              "sw/pkgA/etc/ssl/certs", "sw/pkgB/etc/ssl/certs",
              "etc/ssl/certs", "cwd", "sw/p:g/etc/ssl/certs",
              "sw/[unclosed/sub", "sw/pkgA/etc/ssl/crl",
              "sw/pkgB/etc/ssl/crl", "ca_db");

    # Trusted root and a localhost leaf.
    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Fluffy Trusted Root", @ca_ext,
         "-keyout", "$td/ca1.key", "-out", "$td/ca1.pem") or return 0;
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-addext", "basicConstraints=CA:FALSE",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
         "-keyout", "$td/leaf1.key", "-out", "$td/leaf1.csr") or return 0;
    ossl("x509", "-req", "-days", "1", "-in", "$td/leaf1.csr",
         "-CA", "$td/ca1.pem", "-CAkey", "$td/ca1.key", "-CAcreateserial",
         "-copy_extensions", "copyall", "-out", "$td/leaf1.pem") or return 0;

    # A root that is only reachable through the current directory.
    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Fluffy Untrusted CWD Root", @ca_ext,
         "-keyout", "$td/ca2.key", "-out", "$td/ca2.pem") or return 0;
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=evil.local",
         "-keyout", "$td/leaf2.key", "-out", "$td/leaf2.csr") or return 0;
    ossl("x509", "-req", "-days", "1", "-in", "$td/leaf2.csr",
         "-CA", "$td/ca2.pem", "-CAkey", "$td/ca2.key", "-CAcreateserial",
         "-out", "$td/leaf2.pem") or return 0;

    my $h1 = hash_of("$td/ca1.pem");
    my $h2 = hash_of("$td/ca2.pem");
    return 0 unless $h1 =~ /^[0-9a-f]{8}$/ && $h2 =~ /^[0-9a-f]{8}$/;

    # pkgA: an empty bundle sorts first; pkgB: the real bundle and hash link.
    copy("$td/ca1.pem", "$td/sw/pkgB/etc/ssl/certs/ca-certificates.crt")
        or return 0;
    symlink("$td/ca1.pem", "$td/sw/pkgB/etc/ssl/certs/$h1.0") or return 0;
    symlink("$td/ca1.pem", "$td/sw/p:g/etc/ssl/certs/$h1.0") or return 0;
    spew("$td/sw/pkgA/etc/ssl/certs/ca-certificates.crt", "");
    symlink("$td/ca2.pem", "$td/cwd/$h2.0") or return 0;

    # A leaf that ca1 revokes, and the CRL saying so; pkgA gets an empty
    # CRL file that sorts before it.
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=revoked.local",
         "-keyout", "$td/rev.key", "-out", "$td/rev.csr") or return 0;
    ossl("x509", "-req", "-days", "1", "-in", "$td/rev.csr",
         "-CA", "$td/ca1.pem", "-CAkey", "$td/ca1.key", "-CAcreateserial",
         "-out", "$td/rev.pem") or return 0;
    spew("$td/ca_db/index.txt", "");
    spew("$td/ca_db/crlnumber", "01\n");
    spew("$td/ca.cnf", <<"EOF");
[ ca ]
default_ca = CA_default
[ CA_default ]
database = $td/ca_db/index.txt
crlnumber = $td/ca_db/crlnumber
default_md = sha256
default_crl_days = 1
EOF
    ossl("ca", "-config", "$td/ca.cnf", "-keyfile", "$td/ca1.key",
         "-cert", "$td/ca1.pem", "-revoke", "$td/rev.pem") or return 0;
    ossl("ca", "-config", "$td/ca.cnf", "-keyfile", "$td/ca1.key",
         "-cert", "$td/ca1.pem", "-gencrl",
         "-out", "$td/sw/pkgB/etc/ssl/crl/ca1.pem") or return 0;
    spew("$td/sw/pkgA/etc/ssl/crl/empty.pem", "");
    return 1;
}

my $have_fixture = ok(fixture(), "build CA/leaf/CRL fixture");

SKIP: {
    skip "no fixture", 14 unless $have_fixture;

    my $bundle = "$td/sw/*/etc/ssl/certs/ca-certificates.crt";
    my $crls = "$td/sw/*/etc/ssl/crl/*.pem";

    ok(run(test(["fluffy_glob_test", $crls, "1"])),
       "X509_load_crl_file glob and CONF_get1_default_config_file");

    indir catdir("fx", "cwd") => sub {
        ok(ossl("verify", "-no-CAfile", "-no-CAstore", "-CApath",
                ":$td/sw/*/etc/ssl/certs:$td/etc/ssl/certs", "$td/leaf1.pem"),
           "-CApath wildcard list with empty segments");
        ok(ossl("verify", "-no-CAfile", "-no-CAstore", "-CApath",
                "$td/sw/[unclosed/sub:$td/sw/p[k:]g/etc/ssl/certs",
                "$td/leaf1.pem"),
           "-CApath literal '[' directory and ':' inside a bracket");
        ok(ossl("verify", "-no-CAfile", "-no-CAstore", "-CApath", ".",
                "$td/leaf2.pem"),
           "control: the current directory does hold leaf2's root");
        ok(!ossl("verify", "-no-CAfile", "-no-CAstore", "-CApath",
                 ":$td/sw/*/etc/ssl/certs:", "$td/leaf2.pem"),
           "-CApath empty segments never mean the current directory");
        ok(!ossl("verify", "-no-CAfile", "-no-CAstore", "-CApath", ":",
                 "$td/leaf1.pem"),
           "-CApath ':' alone names no directory");
        ok(ossl("verify", "-no-CApath", "-no-CAstore", "-CAfile", $bundle,
                "$td/leaf1.pem"),
           "-CAfile wildcard skips an empty match");
        ok(ossl("verify", "-no-CApath", "-no-CAstore", "-CAfile", $bundle,
                "-CRLfile", $crls, "-crl_check", "$td/leaf1.pem"),
           "-CRLfile wildcard with -crl_check accepts a good leaf");
        ok(!ossl("verify", "-no-CApath", "-no-CAstore", "-CAfile", $bundle,
                 "-CRLfile", $crls, "-crl_check", "$td/rev.pem"),
           "-CRLfile wildcard with -crl_check rejects a revoked leaf");
        {
            local $ENV{SSL_CERT_FILE} = $bundle;
            local $ENV{SSL_CERT_DIR} = ":$td/sw/*/etc/ssl/certs:";
            ok(ossl("verify", "$td/leaf1.pem"),
               "SSL_CERT_FILE/SSL_CERT_DIR wildcards");
            ok(!ossl("verify", "$td/leaf2.pem"),
               "SSL_CERT_DIR empty segments never mean the current directory");
        }
        ok(!ossl("verify", "-no-CApath", "-no-CAstore", "-CAfile",
                 "$td/sw/*/nonexistent/*.crt", "$td/leaf1.pem"),
           "-CAfile wildcard without matches fails");
        ok(!ossl("verify", "-no-CApath", "-no-CAstore", "-CAfile", "$td/ca2.pem",
                 "$td/leaf1.pem"),
           "-CAfile naming the wrong root fails");
    }, create => 0;

    my @v = run(app(["openssl", "version", "-a"]), capture => 1);
    ok(scalar(grep(/^OPENSSLDIR: "\/sw\/\*\/etc\/ssl"$/, @v)),
       "OPENSSLDIR keeps its literal wildcard");
}
