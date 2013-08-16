package Mojolicious::Plugin::FormValidatorLazy;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
our $VERSION = '0.01';
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode xml_escape hmac_sha1_sum secure_compare b64_decode b64_encode};

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

my $json = Mojo::JSON->new;

### ---
### register
### ---
sub register {
    my ($self, $app, $options) = @_;
    
    my $token_key = $options->{namespace}. "-token";
    
    my $actions =
        ref $options->{action} ? $options->{action} : [$options->{action}];
    
    $app->hook('around_dispatch' => sub {
        (my $next, my $c) = @_;
        
        my $req = $c->req;
        
        if ($req->method eq 'POST' && grep {$_ eq $req->url->path} @$actions) {
            my $token = $c->param($token_key);
            $req->params->remove($token_key);
            if (my $error = validate_form($req, $token, $app->secret)) {
                return $options->{blackhole}->($c, $error);
            }
        }
        
        $next->();
        
        if ($c->res->headers->content_type =~ qr{^text/html}) {
            my $dom = inject_digest($c->res, $actions, $token_key, $app->secret);
            $c->res->body(encode('UTF-8', $dom));
        }
    });
}

sub inject_digest {
    my ($res, $actions, $token_key, $secret) = @_;
    
    my $dom = $res->dom;
    
    for my $action (@$actions) {
        $dom->find(qq{form[action="$action"][method="post"]})->each(sub {
            my $form = shift;
            my $digest = {};
            
            $form->find("*:not([disabled])[name]")->each(sub {
                my $tag = shift;
                my $type = $tag->attr('type');
                my $name = $tag->attr('name');
                $digest->{$name} ||= {};
                
                if (grep {$_ eq $type} qw{hidden checkbox radio submit image}) {
                    push(@{$digest->{$name}->{$DIGEST_KEY_OPTIONS}},
                                                        $tag->attr('value'));
                }
                
                if ($type eq 'submit' || $type eq 'image') {
                    $digest->{$name}->{$DIGEST_KEY_NOT_REQUIRED} //= 1;
                } elsif ($type eq 'checkbox') {
                    $digest->{$name}->{$DIGEST_KEY_NOT_REQUIRED} //= 1;
                } elsif ($type eq 'radio' && ! exists $tag->attr->{checked}) {
                    $digest->{$name}->{$DIGEST_KEY_NOT_REQUIRED} //= 1;
                } elsif ($tag->type eq 'select') {
                    $digest->{$name}->{$DIGEST_KEY_NOT_REQUIRED} = 0;
                    $tag->find('option')->each(sub {
                        push(@{$digest->{$name}->{$DIGEST_KEY_OPTIONS}},
                                                        shift->attr('value'));
                    });
                } elsif ($type eq 'number') {
                    $digest->{$name}->{$DIGEST_KEY_TYPE} = 'number';
                    if (my $val = $tag->attr->{min}) {
                        $digest->{$name}->{$DIGEST_KEY_MIN} = $val;
                    }
                    if (my $val = $tag->attr->{max}) {
                        $digest->{$name}->{$DIGEST_KEY_MAX} = $val;
                    }
                } else {
                    $digest->{$name}->{$DIGEST_KEY_NOT_REQUIRED} = 0;
                    my $maxlength = $tag->attr('maxlength');
                    if ($maxlength =~ /./) {
                        $digest->{$name}->{$DIGEST_KEY_MAXLENGTH} =
                                                            $maxlength;
                    }
                }
                if (exists $tag->attr->{required}) {
                    $digest->{$name}->{$DIGEST_KEY_NOT_NULL} = 1;
                }
                if (my $val = $tag->attr->{pattern}) {
                    $digest->{$name}->{$DIGEST_KEY_PATTERN} = $val;
                }
            });
            
            for my $elem (values %$digest) {
                if (! $elem->{$DIGEST_KEY_NOT_REQUIRED}) {
                    delete $elem->{$DIGEST_KEY_NOT_REQUIRED}
                }
            }
            
            my $signed = sign(digest_encode({
                $DIGEST_KEY2_ACTION => $form->attr('action'),
                $DIGEST_KEY2_DIGEST => $digest,
            }), $secret);
            
            $form->append_content(sprintf(<<"EOF", $token_key, xml_escape $signed));
<div style="display:none">
    <input type="hidden" name="%s" value="%s">
</div>
EOF
        });
    }
    
    return $dom;
}

sub validate_form {
    my ($req, $token, $secret) = @_;
    
    my $params = $req->params;
    my $req_path = $req->url->path;

    if (! $token) {
        return 'Token is not found';
    }
    
    my $unsigned = unsign($token, $secret);
    
    if (! $unsigned) {
        return 'Token has been tampered';
    }
    
    my $digest_wrapper = digest_decode($unsigned);
    my $digest = $digest_wrapper->{$DIGEST_KEY2_DIGEST};
    
    if ($req_path ne $digest_wrapper->{$DIGEST_KEY2_ACTION}) {
        return "Action attribute has been tampered";
    }
    
    for my $name ($params->param) {
        if (! $digest->{$name}) {
            return "Field $name is injected";
        }
    }
    for my $name (keys %{$digest}) {
        if (! grep {$_ eq $name} $params->param) {
            if (! $digest->{$name}->{$DIGEST_KEY_NOT_REQUIRED}) {
                return "Field $name is not given";
            }
        }
        if (my $allowed = $digest->{$name}->{$DIGEST_KEY_OPTIONS}) {
            for my $given ($params->param($name)) {
                if (defined $given && ! grep {$_ eq $given} @$allowed) {
                    return "Field $name has been tampered";
                }
            }
        }
        if (exists $digest->{$name}->{$DIGEST_KEY_MAXLENGTH}) {
            for my $given ($params->param($name)) {
                if (length($given) > $digest->{$name}->{$DIGEST_KEY_MAXLENGTH}) {
                    return "Field $name is too long";
                }
            }
        }
        if (defined $digest->{$name}->{$DIGEST_KEY_NOT_NULL}) {
            for my $given ($params->param($name)) {
                if (! $given || length($given) == 0) {
                    return "Field $name cannot be empty";
                }
            }
        }
        if (my $pattern = $digest->{$name}->{$DIGEST_KEY_PATTERN}) {
            for my $given ($params->param($name)) {
                if ($given !~ /\A$pattern\Z/) {
                    return "Field $name not match pattern";
                }
            }
        }
        if ($digest->{$name}->{$DIGEST_KEY_TYPE} &&
                            $digest->{$name}->{$DIGEST_KEY_TYPE} eq 'number') {
            for my $given ($params->param($name)) {
                if ($given !~ /\A[\d\+\-\.]+\Z/) {
                    return "Field $name not match pattern";
                }
                if (my $min = $digest->{$name}->{$DIGEST_KEY_MIN}) {
                    my $given = scalar $params->param($name);
                    if ($given < $min) {
                        return "Field $name too low";
                    }
                }
                if (my $max = $digest->{$name}->{$DIGEST_KEY_MAX}) {
                    my $given = scalar $params->param($name);
                    if ($given > $max) {
                        return "Field $name too great";
                    }
                }
            }
        }
    }
    return;
}

sub digest_encode {
    return b64_encode($json->encode(shift), '');
}

sub digest_decode {
    return $json->decode(b64_decode(shift));
}

sub sign {
    my ($value, $secret) = @_;
    return $value. '--' . hmac_sha1_sum($value, $secret);
}

sub unsign {
    my ($signed, $secret) = @_;
    if ($signed =~ s/--([^\-]+)$//) {
        my $sig = $1;
        if (secure_compare($sig, hmac_sha1_sum($signed, $secret))) {
            return $signed;
        }
    }
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::FormValidatorLazy - FormValidatorLazy

=head1 SYNOPSIS

    plugin form_validator_lazy => {
        namespace => 'form_validator_lazy',
        action => ['/receptor1'],
        blackhole => sub {
            $_[0]->res->code(400);
            $_[0]->render(text => 'An error occured');
        },
    };

=head1 DESCRIPTION

B<This software is considered to be alpha quality and isn't recommended for
regular usage.>

Mojolicious::Plugin::FormValidatorLazy is a Mojolicious plugin for validating
post data with auto-generated validation rules. The plugin generates validation
rules based on DOM structure and catch the errors.

The plugin detects following error for now.

=over

=item Unknown form fields.

The form fields represented by name attribute are all white listed and post data
injected unknown fields are blocked.

=item Unknown values of selectable fields.

Selectable values of checkboxes, radio buttons and select options are white
listed and unknow values are blocked. 

=item Hidden field tamperings.

Hidden typed input can't be ommited and the value takes only one option. the
plugin blocks values against the rule.

=item Values against maxlength attributes.

Values violating of maxlength are blocked.

=item HTML5 validation attributes

HTML5 supports some validation attributes such as [required], [pattern=*],
[type=number], [min=*], [max=*]. The plugin detects them and block violations.

=back

=head2 CLASS METHODS

=head3 inject_digest

Generates a digest strings of form structure for each forms in mojo response
and inject them into itself.

    my $html = inject_digest($res, ['/path1', '/path2'], $token_key, $secret);

=head3 validate_form

Validates form data of given mojo request by given digest.

    my $error = validate_form($creq, $digest, $secret);

=head2 OPTIONS

=head1 AUTHOR

Sugama Keita, E<lt>sugama@jamadam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Sugama Keita.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
