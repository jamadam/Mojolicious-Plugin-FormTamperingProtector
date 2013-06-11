package Template_Basic;
use Test::Mojo;
use Mojolicious::Lite;
use Test::More tests => 115;
use Data::Dumper;

my $token_key_prefix = 'form-tampering-protecter';

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

{
    no strict 'refs';
    *{__PACKAGE__. '::unsign'} = \&Mojolicious::Plugin::FormValidatorLazy::unsign;
    *{__PACKAGE__. '::digest_decode'} = \&Mojolicious::Plugin::FormValidatorLazy::digest_decode;
    *{__PACKAGE__. '::digest_encode'} = \&Mojolicious::Plugin::FormValidatorLazy::digest_encode;
}

is_deeply digest_decode(digest_encode(["'"])), ["'"];
is_deeply digest_decode(digest_encode(["/"])), ["/"];
is_deeply digest_decode(digest_encode(["\/"])), ["\/"];
is_deeply digest_decode(digest_encode(["\""])), ["\""];
is_deeply digest_decode(digest_encode(["\\\""])), ["\\\""];
is_deeply digest_decode(digest_encode(["\\\/"])), ["\\\/"];
is_deeply digest_decode(digest_encode(["\/\/"])), ["\/\/"];

my $t = Test::Mojo->new;
my $dom;

$t->get_ok('/test1');
$t->status_is(200);

my $token = $t->tx->res->dom->at("form input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {"bar" => {},"baz" => {3 => ["bazValue"]}, foo => {}};
}

my $token2 = $t->tx->res->dom->find('form')->[1]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token2, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {"foo" => {}};
}

my $token3 = $t->tx->res->dom->find('form')->[2]->at("input[name=$token_key_prefix-token]");
is $token3, undef;

my $token4 = $t->tx->res->dom->find('form')->[3]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token4, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {"foo" => {0 => 1, 3 => ["fooValue1", "fooValue2"]}};
}

my $token5 = $t->tx->res->dom->find('form')->[4]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token5, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo1 => {0 => 1, 3 => ["foo1Value"]},foo2 => {0 => 1, 3 => ["foo2Value"]}};
}

my $token6 = $t->tx->res->dom->find('form')->[5]->at("input[name=$token_key_prefix-token]");
is $token6, undef;

my $token7 = $t->tx->res->dom->find('form')->[6]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token7, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo => {3 => ['', "fooValue1", "fooValue2"]}};
}

my $token8 = $t->tx->res->dom->find('form')->[7]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token8, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo1 => {1 => 32}, foo2 => {1 => 0}, foo3 => {}};
}

my $token9 = $t->tx->res->dom->find('form')->[8]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token9, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo1 => {2 => 1}};
}

my $token10 = $t->tx->res->dom->find('form')->[9]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token10, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo => {3 => ['fooValue1', 'fooValue2', 'fooValue3']}};
}

my $token11 = $t->tx->res->dom->find('form')->[10]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token11, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo => {3 => ['', 'fooValue1', 'fooValue2', 'a"b', 'a/b']}};
}

my $token12 = $t->tx->res->dom->find('form')->[11]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token12, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo => {4 => "\\d\\d\\d"}};
}

my $token13 = $t->tx->res->dom->find('form')->[12]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token13, app->secret);
	my $digest = digest_decode($unsigned);
	is_deeply $digest, {foo => {5 => "5", 6 => "10", 7 => 'number'}};
}

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
	"$token_key_prefix-token" => $token2,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor2' => form => {
	foo => 'fooValue',
	bar => 'barValue',
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
	foo => 'fooValue',
	bar => 'barValue',
	"$token_key_prefix-token" => $token2,
});
$t->status_is(400);
$t->content_like(qr{bar});
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

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue1',
	"$token_key_prefix-token" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue5',
	"$token_key_prefix-token" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
	"$token_key_prefix-token" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo1 => 'foo1Value',
	foo2 => 'foo2Value',
	"$token_key_prefix-token" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	"$token_key_prefix-token" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo1 => '',
	"$token_key_prefix-token" => $token5,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo1 => 'a',
	foo2 => '',
	foo3 => 'a',
	"$token_key_prefix-token" => $token8,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo1 => 'a' x 33,
	foo2 => '',
	foo3 => 'a',
	"$token_key_prefix-token" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo1 => '',
	foo2 => 'a',
	foo3 => 'a',
	"$token_key_prefix-token" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo1 => '',
	"$token_key_prefix-token" => $token9,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo1 => '1',
	"$token_key_prefix-token" => $token9,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	"$token_key_prefix-token" => $token10,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue1',
	"$token_key_prefix-token" => $token10,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue1',
	"$token_key_prefix-token" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => '',
	"$token_key_prefix-token" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => 'fooValue3',
	"$token_key_prefix-token" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	"$token_key_prefix-token" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => '333',
	"$token_key_prefix-token" => $token12,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => '3333',
	"$token_key_prefix-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => '33a',
	"$token_key_prefix-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => '',
	"$token_key_prefix-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => '7',
	"$token_key_prefix-token" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => '10',
	"$token_key_prefix-token" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
	foo => '1',
	"$token_key_prefix-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => '22',
	"$token_key_prefix-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => 'a',
	"$token_key_prefix-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
	foo => '',
	"$token_key_prefix-token" => $token12,
});
$t->status_is(400);

1;

__END__
