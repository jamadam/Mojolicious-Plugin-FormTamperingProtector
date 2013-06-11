package Mojolicious::Plugin::FormValidatorLazy;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
our $VERSION = '0.01';
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode xml_escape hmac_sha1_sum secure_compare};

    has 'secret';
    has 'prefix';
    
    my $DIGEST_KEY_ALLOW_NULL = 0;
    my $DIGEST_KEY_MAXLENGTH  = 1;
    my $DIGEST_KEY_REQUIRED   = 2;
    my $DIGEST_KEY_OPTIONS    = 3;
    my $DIGEST_KEY_PATTERN    = 4;
    my $DIGEST_KEY_MIN        = 5;
    my $DIGEST_KEY_MAX        = 6;
    my $DIGEST_KEY_TYPE       = 7;
    
    my $json = Mojo::JSON->new;
    
    ### ---
    ### register
    ### ---
    sub register {
        my ($self, $app, $options) = @_;
        
        $self->secret($app->secret);
        $self->prefix($options->{token_key_prefix});
        
        $app->hook('around_dispatch' => sub {
            (my $app, my $c) = @_;
            
            my @actions =
                ref $options->{action} ? @{$options->{action}} : $options->{action};
            
            if ($c->req->method eq 'POST' && grep {$_ eq $c->req->url->path} @actions) {
                if (my $error = $self->validate_form($c, $self->prefix)) {
                    return $options->{blackhole}->($c, $error);
                }
            }
            
            $app->();
            
            my $dom = $c->res->dom;
            
            for my $action (@actions) {
                $dom->find(qq{form[action="$action"][method="post"]})->each(sub {
                    $self->inject_digest(shift, $self->prefix);
                });
            }
            
            $c->res->body(encode('UTF-8', $dom));
        });
    }
    
    sub inject_digest {
        my ($self, $form, $prefix) = @_;
        my $names = {};
        $form->find("*:not([disabled])[name]")->each(sub {
            my $tag = shift;
            my $type = $tag->attrs('type');
            my $name = $tag->attrs('name');
            $names->{$name} ||= {};
            
            if (grep {$_ eq $type} qw{hidden checkbox radio}) {
                push(@{$names->{$name}->{$DIGEST_KEY_OPTIONS}}, $tag->attrs('value'));
            }
            
            if ($type eq 'checkbox') {
                $names->{$name}->{$DIGEST_KEY_ALLOW_NULL} //= 1;
            } elsif ($type eq 'radio' && ! exists $tag->attrs->{checked}) {
                $names->{$name}->{$DIGEST_KEY_ALLOW_NULL} //= 1;
            } elsif ($tag->type eq 'select') {
                $names->{$name}->{$DIGEST_KEY_ALLOW_NULL} = 0;
                $tag->find('option')->each(sub {
                    push(@{$names->{$name}->{$DIGEST_KEY_OPTIONS}}, shift->attrs('value'));
                });
            } elsif ($type eq 'number') {
                $names->{$name}->{$DIGEST_KEY_TYPE} = 'number';
                if (my $val = $tag->attrs->{min}) {
                    $names->{$name}->{$DIGEST_KEY_MIN} = $val;
                }
                if (my $val = $tag->attrs->{max}) {
                    $names->{$name}->{$DIGEST_KEY_MAX} = $val;
                }
            } else {
                $names->{$name}->{$DIGEST_KEY_ALLOW_NULL} = 0;
                my $maxlength = $tag->attrs('maxlength');
                if ($maxlength =~ /./) {
                    $names->{$name}->{$DIGEST_KEY_MAXLENGTH} = $maxlength;
                }
            }
            if (exists $tag->attrs->{required}) {
                $names->{$name}->{$DIGEST_KEY_REQUIRED} = 1;
            }
            if (my $val = $tag->attrs->{pattern}) {
                $names->{$name}->{$DIGEST_KEY_PATTERN} = $val;
            }
        });
        
        for my $elem (values %$names) {
            if (! $elem->{$DIGEST_KEY_ALLOW_NULL}) {
                delete $elem->{$DIGEST_KEY_ALLOW_NULL}
            }
        }
        
        my $digest = sign(digest_encode($names), $self->secret);
        
        $form->append_content(
            sprintf(<<"EOF", $prefix, xml_escape $digest));
<div style="display:none">
    <input type="hidden" name="%s-token" value="%s">
</div>
EOF
    }
    
    sub validate_form {
        my ($self, $c, $prefix) = @_;
        
        my $token = $c->param("$prefix-token");

        if (! $token) {
            return 'Token is not found';
        }
        
        my $unsigned = unsign($token, $self->secret);
        
        if (! $unsigned) {
            return 'Token has been tampered';
        }
        
        my $digest = digest_decode($unsigned);
        my @form_names = grep {$_ ne "$prefix-token"} $c->param;
        
        for my $name (@form_names) {
            if (! $digest->{$name}) {
                return "Field $name is injected";
            }
        }
        for my $name (keys %{$digest}) {
            if (! grep {$_ eq $name} @form_names) {
                if (! $digest->{$name}->{$DIGEST_KEY_ALLOW_NULL}) {
                    return "Field $name is not given";
                }
            }
            if (my $allowed = $digest->{$name}->{$DIGEST_KEY_OPTIONS}) {
                my $given = scalar $c->param($name);
                if (defined $given && ! grep {$_ eq $given} @$allowed) {
                    return "Field $name has been tampered";
                }
            }
            if (exists $digest->{$name}->{$DIGEST_KEY_MAXLENGTH}) {
                if (length(scalar $c->param($name)) >
                                    $digest->{$name}->{$DIGEST_KEY_MAXLENGTH}) {
                    return "Field $name is too long";
                }
            }
            if (defined $digest->{$name}->{$DIGEST_KEY_REQUIRED}) {
                my $given = scalar $c->param($name);
                if (! $given || length($given) == 0) {
                    return "Field $name cannot be empty";
                }
            }
            if (my $pattern = $digest->{$name}->{$DIGEST_KEY_PATTERN}) {
                my $given = scalar $c->param($name);
                if ($given !~ /\A$pattern\Z/) {
                    return "Field $name not match pattern";
                }
            }
            if ($digest->{$name}->{$DIGEST_KEY_TYPE} &&
                            $digest->{$name}->{$DIGEST_KEY_TYPE} eq 'number') {
                my $given = scalar $c->param($name);
                if ($given !~ /\A[\d\+\-\.]+\Z/) {
                    return "Field $name not match pattern";
                }
                if (my $min = $digest->{$name}->{$DIGEST_KEY_MIN}) {
                    my $given = scalar $c->param($name);
                    if ($given < $min) {
                        return "Field $name too low";
                    }
                }
                if (my $max = $digest->{$name}->{$DIGEST_KEY_MAX}) {
                    my $given = scalar $c->param($name);
                    if ($given > $max) {
                        return "Field $name too great";
                    }
                }
            }
        }
        return;
    }
    
    sub digest_encode {
        my $out = $json->encode(shift);
        $out =~ s{/}{\\/}g;
        $out =~ s{(?<!\\)"}{/}g;
        return $out;
    }
    
    sub digest_decode {
        my $in = shift;
        $in =~ s{(?<!\\)/}{"}g;
        $in =~ s{\\/}{/}g;
        return $json->decode($in);
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
        token_key_prefix => 'form_validator_lazy',
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

=item Unknown form fields.

=item Unknown values of checkboxes or radio buttons.

=item Hidden field tamperings.

=item Form field omittion against require attributes.

=item Values against maxlength attributes.

=head2 OPTIONS

=head1 AUTHOR

Sugama Keita, E<lt>sugama@jamadam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Sugama Keita.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
