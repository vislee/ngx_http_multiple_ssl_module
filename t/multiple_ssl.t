#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Valentin Bartenev
# (C) vislee

# Tests for multiple ssl by Server Name Indication (SNI)

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl sni rewrite/)
	->has('http_multiple_ssl')
	->has_daemon('openssl')
	->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {
}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen       127.0.0.1:8080 ssl;
        server_name  _;

        multiple_ssl on;
        multiple_ssl_cert_path /tmp/;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        multiple_ssl_servernames *.hello.com example.com.crt;
        multiple_ssl_servernames www.vis.com example.com.crt;

        location / {
            return 200 test;
        }

        location /hello/ {
            return 200 hello;
        }
    }

    multiple_ssl_cert_path ./;

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  _;

        multiple_ssl on;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        multiple_ssl_servernames www.vislee.com vislee.com.crt;

        location / {
            return 200 pong;
        }

        location /hello/ {
            return 200 world;
        }
    }
}
EOF

eval { require IO::Socket::SSL; die if $IO::Socket::SSL::VERSION < 1.56; };
plan(skip_all => 'IO::Socket::SSL version >= 1.56 required') if $@;

eval {
	if (IO::Socket::SSL->can('can_client_sni')) {
		IO::Socket::SSL->can_client_sni() or die;
	}
};
plan(skip_all => 'IO::Socket::SSL with OpenSSL SNI support required') if $@;

eval {
	my $ctx = Net::SSLeay::CTX_new() or die;
	my $ssl = Net::SSLeay::new($ctx) or die;
	Net::SSLeay::set_tlsext_host_name($ssl, 'example.com') == 1 or die;
};
plan(skip_all => 'Net::SSLeay with OpenSSL SNI support required') if $@;

$t->plan(12);

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

# system('mkdir -p $d/crt'
# 	. ">>$d/openssl.out 2>&1") == 0
# 	or die "Can't create $d/crt$!\n";

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=vislee.com/ "
	. "-out $d/vislee.com.crt -keyout $d/vislee.com.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for vislee.com: $!\n";

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=example.com/ "
	. "-out /tmp/example.com.crt -keyout /tmp/example.com.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for example.com: $!\n";

$t->run();

###############################################################################

like(get_cert_cn(), qr!/CN=localhost!, 'default cert');
like(get_cert_cn('example.com'), qr!/CN=example.com!, 'spec path sni cert');
like(get_cert_cn('www.hello.com'), qr!/CN=example.com!, 'spec path sni map generic cert');
like(get_cert_cn('www.vis.com'), qr!/CN=example.com!, 'spec path sni map cert');
like(get_cert_cn('test.com'), qr!/CN=localhost!, 'spec path no cert');

like(get_cert_cn('www.vislee.com', 8081), qr!/CN=vislee.com!, 'sni map cert');
like(get_cert_cn('vislee.com', 8081), qr!/CN=vislee.com!, 'sni cert');


# $ssl_server_name in sessions

my $ctx = new IO::Socket::SSL::SSL_Context(
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
	SSL_session_cache_size => 100);

like(get('/', 'localhost', 8080, $ctx), qr/^test$/m, 'ssl server name');
like(get('/', 'example.com', 8080, $ctx), qr/^test$/m, 'ssl server name');
like(get('/hello/', 'example.com', 8080, $ctx), qr/^hello$/m, 'ssl server name');

like(get('/hello/', 'www.vislee.com', 8081, $ctx), qr/^world$/m, 'ssl server name');
like(get('/', 'vislee.com', 8081, $ctx), qr/^pong$/m, 'ssl server name');

###############################################################################

sub get_ssl_socket {
	my ($host, $port, $ctx) = @_;
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1:' . port($port || 8080),
			SSL_hostname => $host,
			SSL_reuse_ctx => $ctx,
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_error_trap => sub { die $_[1] }
		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

sub get_cert_cn {
	my ($host, $port) = @_;
	my $s = get_ssl_socket($host, $port);

	return $s->dump_peer_certificate();
}

sub get {
	my ($uri, $host, $port, $ctx) = @_;
	my $s = get_ssl_socket($host, $port, $ctx) or return;
	my $r = http_get($uri, socket => $s);
	$s->close();
	return $r;
}

###############################################################################