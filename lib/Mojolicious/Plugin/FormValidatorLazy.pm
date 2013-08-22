package Mojolicious::Plugin::FormValidatorLazy;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
our $VERSION = '0.01';
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode decode xml_escape hmac_sha1_sum secure_compare
                                                        b64_decode b64_encode};

my $KEY_ACTION            = 0;
my $KEY_RULES             = 1;
my $RULE_KEY_NOT_REQUIRED = 0;
my $RULE_KEY_MAXLENGTH    = 1;
my $RULE_KEY_NOT_NULL     = 2;
my $RULE_KEY_OPTIONS      = 3;
my $RULE_KEY_PATTERN      = 4;
my $RULE_KEY_MIN          = 5;
my $RULE_KEY_MAX          = 6;
my $RULE_KEY_TYPE         = 7;

my $json = Mojo::JSON->new;

### ---
### register
### ---
sub register {
    my ($self, $app, $opt) = @_;
    
    my $rule_key = $opt->{namespace}. "-rule";
    my $sess_key = $opt->{namespace}. '-sessid';
    
    my $actions =
        ref $opt->{action} ? $opt->{action} : [$opt->{action}];
    
    $app->hook(before_dispatch => sub {
        my $c = shift;
        
        my $req = $c->req;
        
        if ($req->method eq 'POST' && grep {$_ eq $req->url->path} @$actions) {
            
            my $token = $c->param($rule_key);
            $req->params->remove($rule_key);
            
            if (my $err = validate($req, $token, $c->session($sess_key))) {
                return $opt->{blackhole}->($c, $err);
            }
        }
    });
    
    $app->hook(after_dispatch => sub {
        my $c = shift;
        if ($c->res->headers->content_type =~ qr{^text/html}) {
            my $sessid = $c->session($sess_key);
            if (! $sessid) {
                $sessid = hmac_sha1_sum(time(). {}. rand(), $$);
                $c->session($sess_key => $sessid);
            }
            $c->res->body(inject_rule(
                $c->res->body,
                $c->res->content->charset,
                $actions,
                $rule_key,
                $sessid,
            ));
        }
    });
}

sub inject_rule {
    my ($body, $charset, $actions, $token_key, $sessid) = @_;
    
    $body = decode($charset, $body) // $body if $charset;
    my $dom = Mojo::DOM->new($body);
    
    for my $action (@$actions) {
        $dom->find(qq{form[action="$action"][method="post"]})->each(sub {
            my $form    = shift;
            my $rules   = {};
            
            $form->find("*:not([disabled])[name]")->each(sub {
                my $tag = shift;
                my $type = $tag->attr('type');
                my $name = $tag->attr('name');
                $rules->{$name} ||= {};
                
                if (grep {$_ eq $type} qw{hidden checkbox radio submit image}) {
                    push(@{$rules->{$name}->{$RULE_KEY_OPTIONS}},
                                                        $tag->attr('value'));
                }
                
                if ($type eq 'submit' || $type eq 'image') {
                    $rules->{$name}->{$RULE_KEY_NOT_REQUIRED} //= 1;
                } elsif ($type eq 'checkbox') {
                    $rules->{$name}->{$RULE_KEY_NOT_REQUIRED} //= 1;
                } elsif ($type eq 'radio' && ! exists $tag->attr->{checked}) {
                    $rules->{$name}->{$RULE_KEY_NOT_REQUIRED} //= 1;
                } elsif ($tag->type eq 'select') {
                    $rules->{$name}->{$RULE_KEY_NOT_REQUIRED} = 0;
                    $tag->find('option')->each(sub {
                        push(@{$rules->{$name}->{$RULE_KEY_OPTIONS}},
                                                        shift->attr('value'));
                    });
                } elsif ($type eq 'number') {
                    $rules->{$name}->{$RULE_KEY_TYPE} = 'number';
                    if (my $val = $tag->attr->{min}) {
                        $rules->{$name}->{$RULE_KEY_MIN} = $val;
                    }
                    if (my $val = $tag->attr->{max}) {
                        $rules->{$name}->{$RULE_KEY_MAX} = $val;
                    }
                } else {
                    $rules->{$name}->{$RULE_KEY_NOT_REQUIRED} = 0;
                    my $maxlength = $tag->attr('maxlength');
                    if ($maxlength =~ /./) {
                        $rules->{$name}->{$RULE_KEY_MAXLENGTH} = $maxlength;
                    }
                }
                if (exists $tag->attr->{required}) {
                    $rules->{$name}->{$RULE_KEY_NOT_NULL} = 1;
                }
                if (my $val = $tag->attr->{pattern}) {
                    $rules->{$name}->{$RULE_KEY_PATTERN} = $val;
                }
            });
            
            for my $elem (values %$rules) {
                if (! $elem->{$RULE_KEY_NOT_REQUIRED}) {
                    delete $elem->{$RULE_KEY_NOT_REQUIRED}
                }
            }
            
            my $rule_encoded = sign(rule_encode({
                $KEY_ACTION   => $form->attr('action'),
                $KEY_RULES    => $rules,
            }), $sessid);
            
            $form->append_content(sprintf(<<"EOF", $token_key, xml_escape $rule_encoded));
<div style="display:none">
    <input type="hidden" name="%s" value="%s">
</div>
EOF
        });
    }
    
    return encode($charset, $dom->to_xml);
}

sub validate {
    my ($req, $encoded_rule, $sessid) = @_;
    
    if (! $sessid) {
        return 'CSRF is detected';
    }
    
    my $params = $req->params;
    my $req_path = $req->url->path;

    if (! $encoded_rule) {
        return 'Rule is not found';
    }
    
    my $rule_wrapper = rule_decode(unsign($encoded_rule, $sessid));
    
    if (!$rule_wrapper) {
        return 'Rule hsa been tampered';
    }
    
    my $rules = $rule_wrapper->{$KEY_RULES};
    
    if ($req_path ne $rule_wrapper->{$KEY_ACTION}) {
        return "Action attribute has been tampered";
    }
    
    for my $name ($params->param) {
        if (! $rules->{$name}) {
            return "Field $name is injected";
        }
    }
    for my $name (keys %$rules) {
        if (! grep {$_ eq $name} $params->param) {
            if (! $rules->{$name}->{$RULE_KEY_NOT_REQUIRED}) {
                return "Field $name is not given";
            }
        }
        
        my @params = $params->param($name);
        
        if (my $allowed = $rules->{$name}->{$RULE_KEY_OPTIONS}) {
            for my $given (@params) {
                if (! grep {$_ eq $given} @$allowed) {
                    return "Field $name has been tampered";
                }
            }
        }
        if (exists $rules->{$name}->{$RULE_KEY_MAXLENGTH}) {
            for my $given (@params) {
                if (length($given) > $rules->{$name}->{$RULE_KEY_MAXLENGTH}) {
                    return "Field $name is too long";
                }
            }
        }
        if (defined $rules->{$name}->{$RULE_KEY_NOT_NULL}) {
            for my $given (@params) {
                if (length($given) == 0) {
                    return "Field $name cannot be empty";
                }
            }
        }
        if (my $pattern = $rules->{$name}->{$RULE_KEY_PATTERN}) {
            for my $given (@params) {
                if ($given !~ /\A$pattern\Z/) {
                    return "Field $name not match pattern";
                }
            }
        }
        if (($rules->{$name}->{$RULE_KEY_TYPE} || '') eq 'number') {
            for my $given (@params) {
                if ($given !~ /\A[\d\+\-\.]+\Z/) {
                    return "Field $name not match pattern";
                }
                if (my $min = $rules->{$name}->{$RULE_KEY_MIN}) {
                    if ($given < $min) {
                        return "Field $name too low";
                    }
                }
                if (my $max = $rules->{$name}->{$RULE_KEY_MAX}) {
                    if ($given > $max) {
                        return "Field $name too great";
                    }
                }
            }
        }
    }
    return;
}

sub rule_encode {
    return b64_encode($json->encode(shift), '');
}

sub rule_decode {
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
            my ($c, $error) = @_;
            app->log($error);
            $c->res->code(400);
            $c->render(text => 'An error occured');
        },
    };

=head1 DESCRIPTION

B<This software is considered to be alpha quality and isn't recommended for
regular usage.>

Mojolicious::Plugin::FormValidatorLazy is a Mojolicious plugin for validating
post data with auto-generated validation rules out of original forms.
It analizes the HTML forms before sending them to client, generate the rules,
inject it into original forms within a hidden fields so the plugin can detect
the validation rule when a post request comes.

The plugin detects following error for now.

=over

=item Unknown form fields.

The form fields represented by name attribute are all white listed and post data
injected unknown fields are blocked.

=item Unknown values of selectable fields.

Selectable values of checkboxes, radio buttons and select options are white
listed and unknow values are blocked.

The plugin also detects characteristics of tag types. Such as unchecked
checkboxes don't appear to data(not required), radio buttons can't be null only
when default value is offered(not null), and so on.

=item Hidden field tamperings.

Hidden typed input can't be ommited(required) and the value takes only one
option. the plugin blocks values against the rule.

=item Values against maxlength attributes.

Values violating of maxlength are blocked.

=item HTML5 validation attributes

HTML5 supports some validation attributes such as [required], [pattern=*],
[type=number], [min=*], [max=*]. The plugin detects them and block violations.

=item CSRF

This also detects CSRF.

=back

=head2 CLASS METHODS

=head3 inject_rule

Generates a rule strings of form structure for each forms in mojo response
and inject them into itself.

    my $html = inject_rule($res, $charset,
                                ['/path1', '/path2'], $token_key, $session_id);

=head3 validate

Validates form data of given mojo request by given rule.

    my $error = validate($req, $rule, $session_id);

=head1 AUTHOR

Sugama Keita, E<lt>sugama@jamadam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) Sugama Keita.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
