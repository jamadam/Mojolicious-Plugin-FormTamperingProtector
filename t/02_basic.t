package Template_Basic;
use Test::Mojo;
use Mojolicious::Lite;
use Test::More tests => 167;
use Data::Dumper;

my $DIGEST_KEY_NOT_REQUIRED = 0;
my $DIGEST_KEY_MAXLENGTH    = 1;
my $DIGEST_KEY_NOT_NULL     = 2;
my $DIGEST_KEY_OPTIONS      = 3;
my $DIGEST_KEY_PATTERN      = 4;
my $DIGEST_KEY_MIN          = 5;
my $DIGEST_KEY_MAX          = 6;
my $DIGEST_KEY_TYPE         = 7;
my $DIGEST_KEY2_ACTION      = 0;
my $DIGEST_KEY2_DIGEST      = 1;

my $namespace = 'FormValidatorLazy';

plugin form_validator_lazy => {
    namespace => $namespace,
    action => ['/receptor1', '/receptor3'],
    blackhole => sub {
        $_[0]->res->code(400);
        $_[0]->render(text => $_[1]);
    },
};

get '/test1' => sub {
    shift->render('test1');
};

post '/receptor1' => sub {
    my $c = shift;
    is $c->tx->req->param($namespace. '-token'), undef, 'token is cleaned up';
    $c->render(text => 'post completed');
};

post '/receptor2' => sub {
    shift->render(text => 'post completed');
};

post '/receptor3' => sub {
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
is_deeply digest_decode(digest_encode(["やったー"])), ["やったー"];

my $t = Test::Mojo->new;
my $dom;

$t->get_ok('/test1');
$t->status_is(200);

my $token = $t->tx->res->dom->at("form input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			bar => {},
			baz => {
				$DIGEST_KEY_OPTIONS => ["bazValue"],
			},
			foo => {},
			btn => {
				$DIGEST_KEY_NOT_REQUIRED => 1,
				$DIGEST_KEY_OPTIONS => ["send", "send2"],
			},
			btn3 => {
				$DIGEST_KEY_NOT_REQUIRED => 1,
				$DIGEST_KEY_OPTIONS => ["send3"],
			},
		},
	};
}

my $token2 = $t->tx->res->dom->find('form')->[1]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token2, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			"foo" => {},
		},
	}, 'right rule';
}

my $token3 = $t->tx->res->dom->find('form')->[2]->at("input[name=$namespace-token]");
is $token3, undef;

my $token4 = $t->tx->res->dom->find('form')->[3]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token4, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			"foo" => {
				$DIGEST_KEY_NOT_REQUIRED => 1,
				$DIGEST_KEY_OPTIONS => ["fooValue1", "fooValue2"],
			},
		},
	}, 'right rule';
}

my $token5 = $t->tx->res->dom->find('form')->[4]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token5, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_NOT_REQUIRED => 1,
				$DIGEST_KEY_OPTIONS => ["fooValue1","fooValue2"],
			},
	    },
	}, 'right rule';
}

my $token6 = $t->tx->res->dom->find('form')->[5]->at("input[name=$namespace-token]");
is $token6, undef;

my $token7 = $t->tx->res->dom->find('form')->[6]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token7, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_OPTIONS => ['', "fooValue1", "fooValue2"],
			},
		},
	}, 'right rule';
}

my $token8 = $t->tx->res->dom->find('form')->[7]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token8, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo1 => {
				$DIGEST_KEY_MAXLENGTH => 32,
			},
			foo2 => {
				$DIGEST_KEY_MAXLENGTH => 0,
			},
			foo3 => {},
		}
	}, 'right rule';
}

my $token9 = $t->tx->res->dom->find('form')->[8]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token9, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo1 => {
				$DIGEST_KEY_NOT_NULL => 1,
			},
		},
	}, 'right rule';
}

my $token10 = $t->tx->res->dom->find('form')->[9]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token10, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_OPTIONS => ['fooValue1', 'fooValue2', 'fooValue3'],
			},
		},
	}, 'right rule';
}

my $token11 = $t->tx->res->dom->find('form')->[10]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token11, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_OPTIONS => [
					'', 'fooValue1', 'fooValue2', 'a"b', 'a/b',
				],
			},
		},
	}, 'right rule';
}

my $token12 = $t->tx->res->dom->find('form')->[11]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token12, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_PATTERN => "\\d\\d\\d",
			},
		},
	}, 'right rule';
}

my $token13 = $t->tx->res->dom->find('form')->[12]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token13, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_MIN => "5",
				$DIGEST_KEY_MAX => "10",
				$DIGEST_KEY_TYPE => 'number',
			},
		},
	}, 'right rule';
}

my $token14 = $t->tx->res->dom->find('form')->[13]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token14, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor3',
		$DIGEST_KEY2_DIGEST => {},
	};
}

my $token15 = $t->tx->res->dom->find('form')->[14]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token15, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {},
			bar => {},
		},
	}, 'right rule';
}

my $token16 = $t->tx->res->dom->find('form')->[15]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token16, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_OPTIONS => ['value1', 'value2'],
			},
		},
	}, 'right rule';
}

my $token17 = $t->tx->res->dom->find('form')->[16]->at("input[name=$namespace-token]")->attr('value');
{
    my $unsigned = unsign($token17, app->secret);
    my $digest = digest_decode($unsigned);
    is_deeply $digest, {
		$DIGEST_KEY2_ACTION => '/receptor1',
		$DIGEST_KEY2_DIGEST => {
			foo => {
				$DIGEST_KEY_OPTIONS => ['やったー'],
			},
		},
	}, 'right rule';
}

$t->text_is("#jp", 'やったー');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-token" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn => 'send',
    "$namespace-token" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn => 'send2',
    "$namespace-token" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn3 => 'send3',
    "$namespace-token" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn3 => 'tampered',
    "$namespace-token" => $token,
});
$t->status_is(400);
$t->content_like(qr{btn3});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    "$namespace-token" => $token2,
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
    "$namespace-token" => $token,
});
$t->status_is(400);
$t->content_like(qr{biz});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    "$namespace-token" => $token2,
});
$t->status_is(400);
$t->content_like(qr{bar});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-token" => $token,
});
$t->status_is(400);
$t->content_like(qr{foo});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue-tampered!',
    "$namespace-token" => $token,
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
    "$namespace-token" => $token.'-tampered',
});
$t->status_is(400);
$t->content_like(qr{Token});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-token" => 'tampered-'. $token,
});
$t->status_is(400);
$t->content_like(qr{Token});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-token" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue5',
    "$namespace-token" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    "$namespace-token" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => ['fooValue1','invalid'],
    "$namespace-token" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => ['fooValue1','fooValue2'],
    "$namespace-token" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-token" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-token" => $token5,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => 'a',
    foo2 => '',
    foo3 => 'a',
    "$namespace-token" => $token8,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo1 => 'a' x 33,
    foo2 => '',
    foo3 => 'a',
    "$namespace-token" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '',
    foo2 => 'a',
    foo3 => 'a',
    "$namespace-token" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '',
    "$namespace-token" => $token9,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '1',
    "$namespace-token" => $token9,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-token" => $token10,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-token" => $token10,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-token" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-token" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue3',
    "$namespace-token" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    "$namespace-token" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '333',
    "$namespace-token" => $token12,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '3333',
    "$namespace-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '33a',
    "$namespace-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '7',
    "$namespace-token" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '10',
    "$namespace-token" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '1',
    "$namespace-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '22',
    "$namespace-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => 'a',
    "$namespace-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => ['6', 11],
    "$namespace-token" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-token" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor3' => form => {
    "$namespace-token" => $token14,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-token" => $token14,
});
$t->status_is(400);
$t->content_like(qr{Action attribute});

$t->post_ok('/receptor1' => form => {
    foo => 'やったー',
    "$namespace-token" => $token17,
});
$t->status_is(200);

$t->get_ok('/test2.css');
$t->status_is(200);
$t->header_is('Content-Length', 151);

1;

__END__
