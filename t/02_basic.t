package Template_Basic;
use strict;
use warnings;
use utf8;
use Test::Mojo;
use Mojolicious::Lite;
use Test::More tests => 30;

my $token_key_prefix = 'form-tampering-protecter';

plugin form_tampering_protecter => {
	token_key_prefix => $token_key_prefix,
	action => '/receptor1',
	blackhole => sub {
		$_[0]->res->code(400);
		$_[0]->render(text => $_[1]);
	},
};

get '/test1' => sub {
  my $self = shift;
  $self->render(text => <<EOF);
<html>
	<body>
		<form action="/receptor1">
			<input type="text" name="foo" value="fooValue">
			<input type="text" name="bar" value="barValue">
			<input type="hidden" name="baz" value="bazValue">
			<input type="hidden" name="baz" value="bazValue" disabled="disabled">
		</form>
		<span id="jp">やったー</span>
	</body>
</html>
EOF
};

post '/receptor1' => sub {
	shift->render(text => 'post completed');
};

my $t = Test::Mojo->new;
my $dom;

$t->get_ok('/test1');
$t->status_is(200);
my $token = $t->tx->res->dom->at("form input[name=$token_key_prefix-token]")->attrs('value');
like $token, qr/\Q{"names":["foo","bar","baz"],"static":{"baz":"bazValue"}}\E--.+/;
$t->text_is("#jp", 'やったー');

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue',
	bar => 'barValue',
	baz => 'bazValue',
	"$token_key_prefix-token" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue',
	bar => 'barValue',
	baz => 'bazValue',
	biz => 'bizValue',
	"$token_key_prefix-token" => $token,
});
$t->status_is(400);
$t->content_like(qr{biz});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
	bar => 'barValue',
	baz => 'bazValue',
	"$token_key_prefix-token" => $token,
});
$t->status_is(400);
$t->content_like(qr{foo});

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue',
	bar => 'barValue',
	baz => 'bazValue-tampered!',
	"$token_key_prefix-token" => $token,
});
$t->status_is(400);
$t->content_like(qr{baz});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue',
	bar => 'barValue',
	baz => 'bazValue',
});
$t->status_is(400);
$t->content_like(qr{Token});
$t->content_like(qr{not found});

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue',
	bar => 'barValue',
	baz => 'bazValue',
	"$token_key_prefix-token" => $token.'-tampered',
});
$t->status_is(400);
$t->content_like(qr{Token});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue',
	bar => 'barValue',
	baz => 'bazValue',
	"$token_key_prefix-token" => 'tampered-'. $token,
});
$t->status_is(400);
$t->content_like(qr{Token});
$t->content_like(qr{tampered});

1;

__END__
