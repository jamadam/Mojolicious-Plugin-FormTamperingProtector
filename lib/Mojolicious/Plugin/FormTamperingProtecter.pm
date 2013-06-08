package Mojolicious::Plugin::FormTamperingProtecter;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
our $VERSION = '0.01';
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode xml_escape hmac_sha1_sum secure_compare};

    has 'secret';
    has 'prefix';
    
    my $DIGEST_INDEX_OPTIONS    = 0;
    my $DIGEST_INDEX_ALLOW_NULL = 1;
    my $DIGEST_INDEX_MAXLENGTH  = 2;
    my $DIGEST_INDEX_REQUIRED   = 3;
    
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
                if (my $error = $self->tampered($c, $self->prefix)) {
                    return $options->{blackhole}->($c, $error);
                }
            }
            
            $app->();
            
            my $dom = $c->res->dom;
            
            for my $action (@actions) {
                $dom->find(qq{form[action="$action"][method="post"]})->each(sub {
                    $self->inject_token(shift, $self->prefix);
                });
            }
            
            $c->res->body(encode('UTF-8', $dom));
        });
    }
    
    sub inject_token {
        my ($self, $form, $prefix) = @_;
        my $names = {};
        $form->find("*:not([disabled])[name]")->each(sub {
            my $tag = shift;
            my $type = $tag->attrs('type');
            my $name = $tag->attrs('name');
            $names->{$name} ||= [];
            if (grep {$_ eq $type} qw{hidden checkbox radio}) {
                push(@{$names->{$name}->[$DIGEST_INDEX_OPTIONS]}, $tag->attrs('value'));
            }
            if (grep {$_ eq $type} qw{hidden}) {
                $names->{$name}->[$DIGEST_INDEX_ALLOW_NULL] = 0;
            }
            if (grep {$_ eq $type} qw{checkbox radio}) {
                $names->{$name}->[$DIGEST_INDEX_ALLOW_NULL] //= 1;
            }
            my $maxlength = $tag->attrs('maxlength');
            if ($maxlength =~ /./) {
                $names->{$name}->[$DIGEST_INDEX_MAXLENGTH] = $maxlength;
            }
            if (grep {$_ eq 'required'} keys %{$tag->attrs}) {
                $names->{$name}->[$DIGEST_INDEX_REQUIRED] = 1;
            }
        });
        
        my $digest = sign($json->encode($names), $self->secret);
        
        $form->append_content(
            sprintf(qq!<input type="hidden" name="%s-token" value="%s">!,
                    $prefix, xml_escape $digest));
    }
    
    sub tampered {
        my ($self, $c, $prefix) = @_;
        
        my $token = $c->param("$prefix-token");

        if (! $token) {
            return 'Token is not found';
        }
        
        my $unsigned = unsign($token, $self->secret);
        
        if (! $unsigned) {
            return 'Token has been tampered';
        }
        
        my $digest = $json->decode($unsigned);
        my @form_names = grep {$_ ne "$prefix-token"} $c->param;
        
        for my $name (@form_names) {
            if (! $digest->{$name}) {
                return "Field $name is injected";
            }
        }
        for my $name (keys %{$digest}) {
            if (! grep {$_ eq $name} @form_names) {
                if (! $digest->{$name}->[$DIGEST_INDEX_ALLOW_NULL]) {
                    return "Field $name is not given";
                }
            }
            if (my $allowed = $digest->{$name}->[$DIGEST_INDEX_OPTIONS]) {
                my $given = scalar $c->param($name);
                if (defined $given && ! grep {$_ eq $given} @$allowed) {
                    return "Field $name has been tampered";
                }
            }
            my $maxlength = $digest->{$name}->[$DIGEST_INDEX_MAXLENGTH];
            if (defined $maxlength) {
                my $given_length = length(scalar $c->param($name));
                if ($given_length > $maxlength) {
                    return "Field $name is too long";
                }
            }
            if (defined $digest->{$name}->[$DIGEST_INDEX_REQUIRED]) {
                my $given = scalar $c->param($name);
                if (! $given || length($given) == 0) {
                    return "Field $name cannot be empty";
                }
            }
        }
        return;
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

Mojolicious::Plugin::FormTamperingProtecter - FormTamperingProtecter

=head1 SYNOPSIS
  
=head1 DESCRIPTION

=head2 OPTIONS

=head1 AUTHOR

Sugama Keita, E<lt>sugama@jamadam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Sugama Keita.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
