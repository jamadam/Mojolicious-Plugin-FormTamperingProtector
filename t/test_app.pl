#!/usr/bin/env perl
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mojolicious::Lite;

my $token_key_prefix = 'form-tampering-protecter';

app->secret('afewfweweuhu');

plugin form_validator_lazy => {
	token_key_prefix => $token_key_prefix,
	action => '/receptor1',
	blackhole => sub {
		$_[0]->res->code(400);
		$_[0]->render(text => $_[1]);
	},
};

get '/test1' => sub {
    shift->render('test1');
};

post '/receptor1' => sub {
	shift->render(text => 'post completed');
};

post '/receptor2' => sub {
	shift->render(text => 'post completed');
};

app->start;

1;

__END__
