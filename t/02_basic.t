package Template_Basic;
use Test::Mojo;
use Mojolicious::Lite;
use Test::More tests => 172;
use Data::Dumper;
use Mojo::Util qw{b64_decode};

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
    *{__PACKAGE__. '::digest_decode'} = \&Mojolicious::Plugin::FormValidatorLazy::digest_decode;
    *{__PACKAGE__. '::digest_encode'} = \&Mojolicious::Plugin::FormValidatorLazy::digest_encode;
    *{__PACKAGE__. '::unsign'} = \&Mojolicious::Plugin::FormValidatorLazy::unsign;
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

my $sessid = extract_session($t)->{sessid};

my $token = $t->tx->res->dom->find('form')->[0]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
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

my $token2 = $t->tx->res->dom->find('form')->[1]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token2, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            "foo" => {},
        },
    }, 'right rule';
}

my $token3 = $t->tx->res->dom->find('form')->[2]->at("input[name=$namespace-digest]");
is $token3, undef;

my $token4 = $t->tx->res->dom->find('form')->[3]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token4, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            "foo" => {
                $DIGEST_KEY_NOT_REQUIRED => 1,
                $DIGEST_KEY_OPTIONS => ["fooValue1", "fooValue2"],
            },
        },
    }, 'right rule';
}

my $token5 = $t->tx->res->dom->find('form')->[4]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token5, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_NOT_REQUIRED => 1,
                $DIGEST_KEY_OPTIONS => ["fooValue1","fooValue2"],
            },
        },
    }, 'right rule';
}

my $token6 = $t->tx->res->dom->find('form')->[5]->at("input[name=$namespace-digest]");
is $token6, undef;

my $token7 = $t->tx->res->dom->find('form')->[6]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token7, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_OPTIONS => ['', "fooValue1", "fooValue2"],
            },
        },
    }, 'right rule';
}

my $token8 = $t->tx->res->dom->find('form')->[7]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token8, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
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

my $token9 = $t->tx->res->dom->find('form')->[8]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token9, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo1 => {
                $DIGEST_KEY_NOT_NULL => 1,
            },
        },
    }, 'right rule';
}

my $token10 = $t->tx->res->dom->find('form')->[9]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token10, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_OPTIONS => ['fooValue1', 'fooValue2', 'fooValue3'],
            },
        },
    }, 'right rule';
}

my $token11 = $t->tx->res->dom->find('form')->[10]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token11, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_OPTIONS => [
                    '', 'fooValue1', 'fooValue2', 'a"b', 'a/b',
                ],
            },
        },
    }, 'right rule';
}

my $token12 = $t->tx->res->dom->find('form')->[11]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token12, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_PATTERN => "\\d\\d\\d",
            },
        },
    }, 'right rule';
}

my $token13 = $t->tx->res->dom->find('form')->[12]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token13, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_MIN => "5",
                $DIGEST_KEY_MAX => "10",
                $DIGEST_KEY_TYPE => 'number',
            },
        },
    }, 'right rule';
}

my $token14 = $t->tx->res->dom->find('form')->[13]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token14, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor3',
        $DIGEST_KEY2_DIGEST     => {},
    };
}

my $token15 = $t->tx->res->dom->find('form')->[14]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token15, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {},
            bar => {},
        },
    }, 'right rule';
}

my $token16 = $t->tx->res->dom->find('form')->[15]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token16, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
            foo => {
                $DIGEST_KEY_OPTIONS => ['value1', 'value2'],
            },
        },
    }, 'right rule';
}

my $token17 = $t->tx->res->dom->find('form')->[16]->at("input[name=$namespace-digest]")->attr('value');
{
    my $digest = digest_decode(unsign($token17, $sessid));
    is_deeply $digest, {
        $DIGEST_KEY2_ACTION     => '/receptor1',
        $DIGEST_KEY2_DIGEST     => {
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
    "$namespace-digest" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn => 'send',
    "$namespace-digest" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn => 'send2',
    "$namespace-digest" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn3 => 'send3',
    "$namespace-digest" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn3 => 'tampered',
    "$namespace-digest" => $token,
});
$t->status_is(400);
$t->content_like(qr{btn3});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    "$namespace-digest" => $token2,
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
    "$namespace-digest" => $token,
});
$t->status_is(400);
$t->content_like(qr{biz});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    "$namespace-digest" => $token2,
});
$t->status_is(400);
$t->content_like(qr{bar});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-digest" => $token,
});
$t->status_is(400);
$t->content_like(qr{foo});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue-tampered!',
    "$namespace-digest" => $token,
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
$t->content_like(qr{digest}i);
$t->content_like(qr{not found});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-digest" => $token.'-tampered',
});
$t->status_is(400);
$t->content_like(qr{digest}i);
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-digest" => 'tampered-'. $token,
});
$t->status_is(400);
$t->content_like(qr{digest}i);
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-digest" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue5',
    "$namespace-digest" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    "$namespace-digest" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => ['fooValue1','invalid'],
    "$namespace-digest" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => ['fooValue1','fooValue2'],
    "$namespace-digest" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-digest" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-digest" => $token5,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => 'a',
    foo2 => '',
    foo3 => 'a',
    "$namespace-digest" => $token8,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo1 => 'a' x 33,
    foo2 => '',
    foo3 => 'a',
    "$namespace-digest" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '',
    foo2 => 'a',
    foo3 => 'a',
    "$namespace-digest" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '',
    "$namespace-digest" => $token9,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '1',
    "$namespace-digest" => $token9,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-digest" => $token10,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-digest" => $token10,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-digest" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-digest" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue3',
    "$namespace-digest" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    "$namespace-digest" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '333',
    "$namespace-digest" => $token12,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '3333',
    "$namespace-digest" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '33a',
    "$namespace-digest" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-digest" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '7',
    "$namespace-digest" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '10',
    "$namespace-digest" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '1',
    "$namespace-digest" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '22',
    "$namespace-digest" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => 'a',
    "$namespace-digest" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => ['6', 11],
    "$namespace-digest" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-digest" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor3' => form => {
    "$namespace-digest" => $token14,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-digest" => $token14,
});
$t->status_is(400);
$t->content_like(qr{Action attribute});

$t->post_ok('/receptor1' => form => {
    foo => 'やったー',
    "$namespace-digest" => $token17,
});
$t->status_is(200);

$t->get_ok('/test2.css');
$t->status_is(200);
$t->header_is('Content-Length', 151);

$t->post_ok('/receptor3' => form => {
    "$namespace-digest" => $token14,
});
$t->status_is(200);

$t->reset_session;

$t->post_ok('/receptor3' => form => {
    "$namespace-digest" => $token14,
});
$t->status_is(400);
$t->content_like(qr{CSRF});

sub extract_session {
    my $t = shift;
    my $jar = $t->ua->cookie_jar;
    my $app = $t->app;
    my $session_name = $app->sessions->cookie_name || 'mojolicious';
    my ($session_cookie) = grep { $_->name eq $session_name } $jar->all;
    return unless $session_cookie;
    (my $value = $session_cookie->value) =~ s/--([^\-]+)$//;
    $value =~ tr/-/=/;
    my $session = Mojo::JSON->new->decode(b64_decode $value);
    return $session;
}

1;

__END__
