package Mojolicious::Plugin::FormTamperingProtecter;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
our $VERSION = '0.01';
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode xml_escape hmac_sha1_sum secure_compare};

    has 'secret';
    
    my $json = Mojo::JSON->new;
    
    ### ---
    ### register
    ### ---
    sub register {
        my ($self, $app, $options) = @_;
        
        $self->secret($app->secret);
        
        $app->hook('around_dispatch' => sub {
            (my $app, my $c) = @_;
            
            my $token_key_prefix = $options->{token_key_prefix};
            
            my @actions =
                ref $options->{action} ? @{$options->{action}} : $options->{action};
            
            if ($c->req->method eq 'POST' && grep {$_ eq $c->req->url->path} @actions) {
                if (my $error = $self->tampered($c, $token_key_prefix)) {
                    return $options->{blackhole}->($c, $error);
                }
            }
            
            $app->();
            
            my $dom = $c->res->dom;
            
            for my $action (@actions) {
                $dom->find("form[action=$action]")->each(sub {
                    my $form = shift;
                    my $names = {};
                    my $static = {};
                    $form->find("*[name]")->each(sub {
                        my $tag = shift;
                        if ($tag->attrs('disabled')) {
                            return;
                        }
                        my $name = $tag->attrs('name');
                        $names->{$name}++;
                        if (grep {$_ eq $tag->attrs('type')} @{['hidden', 'checkbox']}) {
                            if ($static->{$name}) {
                                if (ref $static->{$name}) {
                                    push(@{$static->{$name}}, $tag->attrs('value'));
                                } else {
                                    $static->{$name} = [
                                        $static->{$name},
                                        $tag->attrs('value')
                                    ];
                                }
                            } else {
                                $static->{$name} = $tag->attrs('value');
                            }
                        }
                    });
                    my $digest = sign(
                        $json->encode({names => [sort keys(%$names)], static => $static}
                    ), $self->secret);
                    
                    my $digest_html = xml_escape $digest;
                    $form->append_content(
                        qq!<input type="hidden" name="$token_key_prefix-token" value="$digest_html">!);
                });
            }
            $c->res->body(encode('UTF-8', $dom));
        });
    }
    
    sub tampered {
        my ($self, $c, $token_key_prefix) = @_;
        
        my $token = $c->param("$token_key_prefix-token");

        if (! $token) {
            return 'Token not found';
        }
        
        my $unsigned = unsign($token, $self->secret);
        
        if (! $unsigned) {
            return 'Token has tampered';
        }
        
        my $digest = $json->decode($unsigned);
        my @form_names = sort grep {$_ ne "$token_key_prefix-token"} $c->param;
        
        for my $name (@form_names) {
            if (! grep {$_ eq $name} @{$digest->{'names'}}) {
                return "Form key $name is injected";
            }
        }
        for my $name (@{$digest->{'names'}}) {
            if (! grep {$_ eq $name} @form_names) {
                return "Form key $name not given";
            }
        }
        for my $name (keys %{$digest->{'static'}}) {
            my $candidates = $digest->{'static'}->{$name};
            $candidates = (ref $candidates) ? $candidates : [$candidates];
            if (!grep {$_ eq $c->param($name)} @$candidates) {
                return "Hidden field $name has tampered";
            }
        }
        return;
    }
    
    sub sign {
        my ($value, $secret) = @_;
        return "$value--" . hmac_sha1_sum($value, $secret);
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
