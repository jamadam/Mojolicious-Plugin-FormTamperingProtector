package Template_Basic;
use Test::Mojo;
use Mojo::JSON;
use Mojolicious::Lite;
use Test::More tests => 85;
use Data::Dumper;

my $token_key_prefix = 'form-tampering-protecter';
my $json = Mojo::JSON->new;

plugin form_tampering_protecter => {
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

my $t = Test::Mojo->new;
my $dom;

$t->get_ok('/test1');
$t->status_is(200);

{
    no strict 'refs';
    *{__PACKAGE__. '::contain'} = \&Mojolicious::Plugin::FormTamperingProtecter::contain;
    *{__PACKAGE__. '::unsign'} = \&Mojolicious::Plugin::FormTamperingProtecter::unsign;
}

my $token = $t->tx->res->dom->at("form input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token, app->secret);
	my $digest = $json->decode($unsigned);
	# is_deeply $digest, {"names" => ["bar","baz","foo"],"static" => {"baz" => ["bazValue"]}};
	is scalar @{$digest->{names}}, 3;
	ok contain('bar', $digest->{names});
	ok contain('baz', $digest->{names});
	ok contain('foo', $digest->{names});
	is scalar keys %{$digest->{static}}, 1;
	is scalar @{$digest->{static}->{baz}}, 1;
	ok contain('bazValue', $digest->{static}->{baz});
}

my $token2 = $t->tx->res->dom->find('form')->[1]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token2, app->secret);
	my $digest = $json->decode($unsigned);
	#is_deeply $digest, {"names" => ["foo"],"static" => {}};
	is scalar @{$digest->{names}}, 1;
	ok contain('foo', $digest->{names});
	is scalar keys %{$digest->{static}}, 0;
}

my $token3 = $t->tx->res->dom->find('form')->[2]->at("input[name=$token_key_prefix-token]");
is $token3, undef;

my $token4 = $t->tx->res->dom->find('form')->[3]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token4, app->secret);
	my $digest = $json->decode($unsigned);
	#is_deeply $digest, {"names" => ["foo"],"static" => {"foo" => [undef, "fooValue1", "fooValue2"]}};
	is scalar @{$digest->{names}}, 1;
	ok contain('foo', $digest->{names});
	is scalar keys %{$digest->{static}}, 1;
	ok contain('fooValue1', $digest->{static}->{foo});
	ok contain('fooValue2', $digest->{static}->{foo});
}

my $token5 = $t->tx->res->dom->find('form')->[4]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token5, app->secret);
	my $digest = $json->decode($unsigned);
	#is_deeply $digest, {"names" => ["foo1", "foo2"],"static" => {"foo1" => [undef, "foo1Value"], "foo2" => [undef, "foo2Value"]}};
	is scalar @{$digest->{names}}, 2;
	ok contain('foo1', $digest->{names});
	ok contain('foo2', $digest->{names});
	is scalar keys %{$digest->{static}}, 2;
	ok contain(undef, $digest->{static}->{foo1});
	ok contain('foo1Value', $digest->{static}->{foo1});
	ok contain(undef, $digest->{static}->{foo2});
	ok contain('foo2Value', $digest->{static}->{foo2});
}

my $token6 = $t->tx->res->dom->find('form')->[5]->at("input[name=$token_key_prefix-token]");
is $token6, undef;

my $token7 = $t->tx->res->dom->find('form')->[6]->at("input[name=$token_key_prefix-token]")->attrs('value');
{
	my $unsigned = unsign($token7, app->secret);
	my $digest = $json->decode($unsigned);
	#is_deeply $digest, {"names" => ["foo"],"static" => {"foo" => ['', undef, "fooValue1", "fooValue2"]}};
	is scalar @{$digest->{names}}, 1;
	ok contain('foo', $digest->{names});
	is scalar keys %{$digest->{static}}, 1;
	ok contain(undef, $digest->{static}->{foo});
	ok contain('', $digest->{static}->{foo});
	ok contain('fooValue1', $digest->{static}->{foo});
	ok contain('fooValue2', $digest->{static}->{foo});
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

1;

__END__
