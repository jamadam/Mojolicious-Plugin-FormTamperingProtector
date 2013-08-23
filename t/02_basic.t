package Template_Basic;
use Test::Mojo;
use Mojolicious::Lite;
use Test::More tests => 181;
use Data::Dumper;
use Mojo::Util qw{b64_decode};

my $KEY_ACTION            = 0;
my $KEY_RULES             = 1;
my $KEY_REQUIRED     	  = 2;
my $RULE_KEY_MAXLENGTH    = 1;
my $RULE_KEY_NOT_NULL     = 2;
my $RULE_KEY_OPTIONS      = 3;
my $RULE_KEY_PATTERN      = 4;
my $RULE_KEY_MIN          = 5;
my $RULE_KEY_MAX          = 6;
my $RULE_KEY_TYPE         = 7;

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
    *{__PACKAGE__. '::rule_decode'} = \&Mojolicious::Plugin::FormValidatorLazy::rule_decode;
    *{__PACKAGE__. '::rule_encode'} = \&Mojolicious::Plugin::FormValidatorLazy::rule_encode;
    *{__PACKAGE__. '::unsign'} = \&Mojolicious::Plugin::FormValidatorLazy::unsign;
}

is_deeply rule_decode(rule_encode(["'"])), ["'"];
is_deeply rule_decode(rule_encode(["/"])), ["/"];
is_deeply rule_decode(rule_encode(["\/"])), ["\/"];
is_deeply rule_decode(rule_encode(["\""])), ["\""];
is_deeply rule_decode(rule_encode(["\\\""])), ["\\\""];
is_deeply rule_decode(rule_encode(["\\\/"])), ["\\\/"];
is_deeply rule_decode(rule_encode(["\/\/"])), ["\/\/"];
is_deeply rule_decode(rule_encode(["やったー"])), ["やったー"];

my $t = Test::Mojo->new;
my $dom;

$t->get_ok('/test1');
$t->status_is(200);

my $sessid = extract_session($t)->{$namespace. '-sessid'};

my $token = $t->tx->res->dom->find('form')->[0]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo', 'bar', 'baz'],
        $KEY_RULES    => {
            bar => {},
            baz => {
                $RULE_KEY_OPTIONS => ["bazValue"],
            },
            foo => {},
            yada => {
                $RULE_KEY_OPTIONS => ["yadaValue"],
            },
            btn => {
                $RULE_KEY_OPTIONS => ["send", "send2"],
            },
            btn3 => {
                $RULE_KEY_OPTIONS => ["send3"],
            },
        },
    };
}

my $token2 = $t->tx->res->dom->find('form')->[1]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token2, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES     => {
            "foo" => {},
        },
    }, 'right rule';
}

my $token3 = $t->tx->res->dom->find('form')->[2]->at("input[name=$namespace-rule]");
is $token3, undef;

my $token4 = $t->tx->res->dom->find('form')->[3]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token4, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => [],
        $KEY_RULES    => {
            "foo" => {
                $RULE_KEY_OPTIONS => ["fooValue1", "fooValue2", "fooValue3", "fooValue4"],
            },
        },
    }, 'right rule';
}

my $token5 = $t->tx->res->dom->find('form')->[4]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token5, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => [],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => ["fooValue1","fooValue2","fooValue3","fooValue4"],
            },
        },
    }, 'right rule';
}

my $token6 = $t->tx->res->dom->find('form')->[5]->at("input[name=$namespace-rule]");
is $token6, undef;

my $token7 = $t->tx->res->dom->find('form')->[6]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token7, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => ['', "fooValue1", "fooValue2"],
            },
        },
    }, 'right rule';
}

my $token8 = $t->tx->res->dom->find('form')->[7]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token8, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo1','foo2','foo3'],
        $KEY_RULES    => {
            foo1 => {
                $RULE_KEY_MAXLENGTH => 32,
            },
            foo2 => {
                $RULE_KEY_MAXLENGTH => 0,
            },
            foo3 => {},
        }
    }, 'right rule';
}

my $token9 = $t->tx->res->dom->find('form')->[8]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token9, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo1'],
        $KEY_RULES    => {
            foo1 => {
                $RULE_KEY_NOT_NULL => 1,
            },
        },
    }, 'right rule';
}

my $token10 = $t->tx->res->dom->find('form')->[9]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token10, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => ['fooValue1', 'fooValue2', 'fooValue3'],
            },
        },
    }, 'right rule';
}

my $token11 = $t->tx->res->dom->find('form')->[10]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token11, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => [
                    '', 'fooValue1', 'fooValue2', 'a"b', 'a/b',
                ],
            },
        },
    }, 'right rule';
}

my $token12 = $t->tx->res->dom->find('form')->[11]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token12, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_PATTERN => "\\d\\d\\d",
            },
        },
    }, 'right rule';
}

my $token13 = $t->tx->res->dom->find('form')->[12]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token13, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_MIN => "5",
                $RULE_KEY_MAX => "10",
                $RULE_KEY_TYPE => 'number',
            },
        },
    }, 'right rule';
}

my $token14 = $t->tx->res->dom->find('form')->[13]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token14, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor3',
		$KEY_REQUIRED => [],
        $KEY_RULES    => {},
    };
}

my $token15 = $t->tx->res->dom->find('form')->[14]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token15, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo','bar'],
        $KEY_RULES    => {
            foo => {},
            bar => {},
        },
    }, 'right rule';
}

my $token16 = $t->tx->res->dom->find('form')->[15]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token16, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => ['value1', 'value2'],
            },
        },
    }, 'right rule';
}

my $token17 = $t->tx->res->dom->find('form')->[16]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token17, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => ['foo'],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => ['やったー'],
            },
        },
    }, 'right rule';
}

my $token18 = $t->tx->res->dom->find('form')->[17]->at("input[name=$namespace-rule]")->attr('value');
{
    my $rule = rule_decode(unsign($token18, $sessid));
    is_deeply $rule, {
        $KEY_ACTION   => '/receptor1',
		$KEY_REQUIRED => [],
        $KEY_RULES    => {
            foo => {
                $RULE_KEY_OPTIONS => ['fooValue1', 'fooValue2', 'fooValue3'],
            },
        },
    }, 'right rule';
}

$t->text_is("#jp", 'やったー');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-rule" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    yada => 'yadaValue',
    "$namespace-rule" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn => 'send',
    "$namespace-rule" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn => 'send2',
    "$namespace-rule" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn3 => 'send3',
    "$namespace-rule" => $token,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    btn3 => 'tampered',
    "$namespace-rule" => $token,
});
$t->status_is(400);
$t->content_like(qr{btn3});
$t->content_like(qr{tampered});

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
    "$namespace-rule" => $token,
});
$t->status_is(400);
$t->content_like(qr{biz});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-rule" => $token,
});
$t->status_is(400);
$t->content_like(qr{foo});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue-tampered!',
    "$namespace-rule" => $token,
});
$t->status_is(400);
$t->content_like(qr{baz});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    yada => 'yadaValue-tampered!',
    "$namespace-rule" => $token,
});
$t->status_is(400);
$t->content_like(qr{yada});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
});
$t->status_is(400);
$t->content_like(qr{rule}i);
$t->content_like(qr{not found});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-rule" => $token.'-tampered',
});
$t->status_is(400);
$t->content_like(qr{rule}i);
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    baz => 'bazValue',
    "$namespace-rule" => 'tampered-'. $token,
});
$t->status_is(400);
$t->content_like(qr{rule}i);
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    "$namespace-rule" => $token2,
});
$t->status_is(200);
$t->content_is('post completed');

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue',
    bar => 'barValue',
    "$namespace-rule" => $token2,
});
$t->status_is(400);
$t->content_like(qr{bar});
$t->content_like(qr{injected});

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-rule" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue5',
    "$namespace-rule" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    "$namespace-rule" => $token4,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => ['fooValue1','invalid'],
    "$namespace-rule" => $token4,
});
$t->status_is(400);
$t->content_like(qr{foo});
$t->content_like(qr{tampered});

$t->post_ok('/receptor1' => form => {
    foo => ['fooValue1','fooValue2'],
    "$namespace-rule" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-rule" => $token5,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-rule" => $token5,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => 'a',
    foo2 => '',
    foo3 => 'a',
    "$namespace-rule" => $token8,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo1 => 'a' x 33,
    foo2 => '',
    foo3 => 'a',
    "$namespace-rule" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '',
    foo2 => 'a',
    foo3 => 'a',
    "$namespace-rule" => $token8,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '',
    "$namespace-rule" => $token9,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo1 => '1',
    "$namespace-rule" => $token9,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-rule" => $token10,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-rule" => $token10,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue1',
    "$namespace-rule" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-rule" => $token11,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => 'fooValue3',
    "$namespace-rule" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    "$namespace-rule" => $token11,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '333',
    "$namespace-rule" => $token12,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '3333',
    "$namespace-rule" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '33a',
    "$namespace-rule" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-rule" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '',
    "$namespace-rule" => $token12,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '7',
    "$namespace-rule" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '10',
    "$namespace-rule" => $token13,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    foo => '1',
    "$namespace-rule" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => '22',
    "$namespace-rule" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => 'a',
    "$namespace-rule" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor1' => form => {
    foo => ['6', 11],
    "$namespace-rule" => $token13,
});
$t->status_is(400);

$t->post_ok('/receptor3' => form => {
    "$namespace-rule" => $token14,
});
$t->status_is(200);

$t->post_ok('/receptor1' => form => {
    "$namespace-rule" => $token14,
});
$t->status_is(400);
$t->content_like(qr{Action attribute});

$t->post_ok('/receptor1' => form => {
    foo => 'やったー',
    "$namespace-rule" => $token17,
});
$t->status_is(200);

$t->get_ok('/test2.css');
$t->status_is(200);
$t->header_is('Content-Length', 151);

$t->post_ok('/receptor3' => form => {
    "$namespace-rule" => $token14,
});
$t->status_is(200);

$t->reset_session;

$t->post_ok('/receptor3' => form => {
    "$namespace-rule" => $token14,
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
