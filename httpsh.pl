#!/usr/bin/perl
 
use strict;
use warnings;
 
use LWP::Socket;
use FCGI::ProcManager qw/ pm_manage pm_pre_dispatch pm_post_dispatch /;
use URI;
use URI::QueryParam;
use Authen::PAM;
use Net::Netmask;
use Cwd 'abs_path';
use POSIX qw/ strftime /;

my $workdir = abs_path($0);
$workdir =~ s/httpsh[.]pl//g;
my $command_dir = $workdir . "commands";
my $errlog = $workdir . "log/error.log";
my @allow_ip = ('127.0.0.1');

sub check_client {
	my ($ip, @ranges) = @_;
	foreach my $range (@ranges) {
		my $block = new Net::Netmask($range);
		if ($block->match($ip)) {
			return 1;
		}
	}
	printlog("[WAR] IP is not in whitelist");
	return 0;
}

sub pass_auth {
    my ($login, $pass) = @_;
    my $pamh;
    pam_start("passwd", $login, sub {((0, $pass) x (@_/2), PAM_SUCCESS())}, $pamh);
    my $res = pam_authenticate($pamh) == PAM_SUCCESS();
    pam_end($pamh);
    return $res;
}

sub get_query {
	my ($request) = @_;
	my @headers = split(/\r\n/, $request);
	my $header = $headers[0];
	if($header =~ /GET \/([^ ]*) HTTP.+/i) {
		return $1;
	}
	return 0;
}

sub get_credentials {
	my ($request) = @_;
	my @headers = split(/\r\n/, $request);
	foreach my $header (@headers) {
		if($header =~ /Auth-Token:[ ]*([^:]+)[:](.*)$/i) {
			return ($1, $2);
		}
	}
	return (0, 0);
}

sub http_response {
	my ($socket, $status, $content) = @_;
	my $headers = 
		"HTTP/1.1 %d OK\r\n"
	. 	"Server: HttpToShell 1.0\r\n"
	. 	"Content-Type: text/plain\r\n"
	. 	"Content-Length: %d\r\n"
	. 	"Connection: close\r\n\r\n";
	$socket->write(sprintf($headers, $status, length $content));
	$socket->write($content);
}

sub convert_params {
	my ($uri) = @_;
	my $scriptparams = "";
	my $paramval;
	my $paramkey;
	my $paramkeyval;
	my $command;
	for $paramkey ($uri->query_param) {
		$paramval = $uri->query_param($paramkey);
		$paramkey =~ s/([\\'"`\$])/\\$1/g;
		$paramval =~ s/([\\'"`\$])/\\$1/g;
		$paramkeyval = join('', '--', $paramkey, ' "', $paramval, '"');
		$scriptparams = join(' ', $scriptparams, $paramkeyval);
	}
	return $scriptparams;
}

sub printlog {
	my ($message) = @_;
	print strftime('%Y-%m-%d %H:%M:%S', localtime), ": ", $message, "\n";
}

printlog("[INF] Starting server");
my $sock = new LWP::Socket();
die "[ERR] Can't bind a socket\n" unless $sock->bind('127.0.0.1', '2424');
$sock->listen(10);
pm_manage(n_processes => 5);

while (my $socket = $sock->accept(10)) {
	my @sockname = $socket->getsockname();
	printlog("[INF] Connection accepted: $sockname[0]");
	pm_pre_dispatch();
	my $request;
	if (check_client($sockname[0], @allow_ip)) {
		$socket->read(\$request);
		my @credentials = get_credentials($request);
		if (not $credentials[0]) {
			printlog("[WAR] Auth token not found");
			http_response($socket, 400, "Bad request");
		} elsif (not pass_auth($credentials[0], $credentials[1])) {
			printlog("[WAR] Auth not passed");
			http_response($socket, 403, "Forbidden");
		} else {
			my $query = get_query($request);
			if (not $query) {
				printlog("[WAR] Invalid query");
				http_response($socket, 400, "Bad request");
			} else {
				printlog("[INF] Query: $query");
				my $uri = URI->new($query);
				my $path = $uri->path();
				my $scriptname = join('/', $command_dir, $path);
				if (-e $scriptname) {
					my $scriptparams = convert_params($uri);
					my $command = sprintf('sudo -H -u %s %s %s 2>>%s', $credentials[0], $scriptname, $scriptparams, $errlog);
					printlog("[INF] Executing: $command");
					my $content = qx($command);
					http_response($socket, 200, $content);
				} else {
					printlog("[WAR] Command not found: $path");
					http_response($socket, 404, "Not found");
				}
			}
		}
	}
	printlog("[INF] Closing connection");
	$socket->shutdown();
	pm_post_dispatch();
}
printlog("[INF] Shooting server down");
$sock->shutdown();
