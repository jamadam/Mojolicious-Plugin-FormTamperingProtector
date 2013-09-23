#!/usr/bin/env perl
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mojolicious::Lite;
use Plack::Builder;

my $token_key_prefix = 'FormValidatorLazy';

app->secret('afewfweweuhu2');

get '/test1' => sub {
    shift->render('test1');
};

post '/receptor1' => sub {
    shift->render(text => 'post completed');
};

post '/receptor2' => sub {
    shift->render(text => 'post completed');
};

builder {
    enable 'Session';
    enable 'Plack::Middleware::FormValidatorLazy',
        namespace => $token_key_prefix,
        action => '/receptor1',
        secret => 'afewfweweuhu',
        blackhole => sub {
            my ($env, $err) = @_;
            return [
                403,
                [
                    'Content-Type' => 'text/plain',
                    'Content-Length' => length($err),
                ],
                [$err],
            ];
        };
    app->start;
};

__END__
