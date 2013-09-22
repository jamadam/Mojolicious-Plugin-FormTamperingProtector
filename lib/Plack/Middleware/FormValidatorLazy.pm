package Plack::Middleware::FormValidatorLazy;
use strict;
use warnings;
use parent qw(Plack::Middleware);
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode decode xml_escape hmac_sha1_sum secure_compare
                                                        b64_decode b64_encode};
use HTML::ValidationRules::Legacy;
use Plack::Util::Accessor qw(header_get namespace action secret);
use Plack::Request;
use Plack::Response;
use Plack::Util qw(header_get);

our $TERM_ACTION = 0;
our $TERM_SCHEMA = 1;

my $json = Mojo::JSON->new;
my $schema_key;
my $sess_key;
my $actions;

sub prepare_app {
    my $self = shift;
    $schema_key  = $self->{namespace}. "-schema";
    $sess_key    = $self->{namespace}. '-sessid';
    $actions     = ref $self->{action} ? $self->{action} : [$self->{action}];
    if (! $self->{secret}) {
        die 'secret is empty';
    }
}

### ---
### call
### ---
sub call {
    my($self, $env) = @_;
    warn Dumper($env);
    my $req = Mojo::Message::Request->new->parse($env);
    my $req2 = Plack::Request->new($env);
    
    if ($req->method eq 'POST' && grep {$_ eq $req->url->path} @$actions) {
        
        if (! $env->{'psgix.input.buffered'}) {
            # TODO 
        }
        
        warn $req2->body;
        
=test
        my $input = $env->{'psgi.input'};
        $input->seek(0, 0);
        my $buf = '';
        my $cl = $env->{CONTENT_LENGTH};
        while (my $l = $input->read(my $chunk, $cl < 131072 ? $cl : 131072)) {
            $cl -= $l;
            if ($l) {
                $buf .= $chunk;
            }
        }
        $input->seek(0,0);
        warn $buf;
        #---------
=cut

        
        my $wrapper = deserialize(unsign(
            $req->params($schema_key),
            unsign($req->cookie($sess_key)->value, $self->secret)
        ));
        
        $req->params->remove($schema_key);
        
        if (!$wrapper) {
            return $self->{blackhole}->($env, 'Form schema is missing, possible hacking attempt');
        }
        
        if ($req->path ne $wrapper->{$TERM_ACTION}) {
            return $self->{blackhole}->($env, 'Action attribute has been tampered');
        }
        
        if (my $err = HTML::ValidationRules::Legacy::validate($wrapper->{$TERM_SCHEMA}, $req->params)) {
            return $self->{blackhole}->($env, $err);
        }
    }
    
    my $res = $self->app->($env);
    
    return $self->response_cb($res, sub {
        my $res = shift;
        
        if (Plack::Util::header_get($res->[1], 'Content-Type') =~
                                    qr{^text/html(?:;\s?(?:charset=([^;]+)))?}
                                                    ) {
            my $charset = $1;
            
            my $sessid = unsign($req->cookie($sess_key), $self->secret);
            
            if (! $sessid) {
                $sessid = hmac_sha1_sum(time(). {}. rand(), $$);
                set_cookie($res, $sess_key, sign($sessid, $self->secret));
            }
            
            return sub {
                if (my $body_chunk = shift) {
                    $body_chunk = inject(
                        $body_chunk, $actions, $schema_key, $sessid, $charset);
                    return $body_chunk;
                }
            };
        }
    });
}

sub set_cookie {
    my ($res, $key, $value) = @_;
    my $response = Plack::Response->new(@$res);
    $response->cookies->{$key} = {value => $value};

    my $final_r = $response->finalize;
    $res->[1] = $final_r->[1]; # headers
}

sub inject {
    my ($html, $actions, $token_key, $sessid, $charset) = @_;
    
    if (! ref $html) {
        $html = Mojo::DOM->new($charset ? decode($charset, $html) : $html);
    }

    $html->find(qq{form[action][method="post"]})->each(sub {
        my $form    = shift;
        my $action  = $form->attr('action');
        
        if (! grep {$_ eq $action} @$actions) {
            return;
        }
        
        my $wrapper = sign(serialize({
            $TERM_ACTION    => $action,
            $TERM_SCHEMA    => HTML::ValidationRules::Legacy::extract($form, $charset),
        }), $sessid);
        
        $form->append_content(sprintf(<<"EOF", $token_key, xml_escape $wrapper));
<div style="display:none">
    <input type="hidden" name="%s" value="%s">
</div>
EOF
    });
    
    return encode($charset, $html);
}

sub serialize {
    return b64_encode($json->encode(shift || ''), '');
}

sub deserialize {
    return $json->decode(b64_decode(shift || ''));
}

sub sign {
    my ($value, $session_id) = @_;
    warn $session_id;
    return $value. '--' . hmac_sha1_sum($value, $session_id);
}

sub unsign {
    my ($value, $session_id) = @_;
    warn $session_id;
    if ($value && $session_id && $value =~ s/--([^\-]+)$//) {
        my $sig = $1;
        if (secure_compare($sig, hmac_sha1_sum($value, $session_id))) {
            return $value;
        }
    }
}

1;

__END__

=head1 NAME

Plack::Middleware::FormValidatorLazy - FormValidatorLazy

=head1 SYNOPSIS

    use Plack::Middleware::FormValidatorLazy;
    
    builder {
        enable "FormValidatorLazy", {
            namespace => 'form_validator_lazy',
            action => ['/receptor1'],
            blackhole => sub {
                my ($env, $error) = @_;
                app->log($error);
                $c->res->code(400);
                $c->render(text => 'An error occured');
            },
        }
        $app;
    };

=head1 DESCRIPTION

B<This software is considered to be alpha quality and isn't recommended for
regular usage.>

Mojolicious::Plugin::FormValidatorLazy is a Mojolicious plugin for validating
post data with auto-generated validation rules out of original forms.
It analizes the HTML forms before sending them to client, generate the schema,
inject it into original forms within a hidden fields so the plugin can detect
the schema when a post request comes.

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
option. the plugin blocks values against the schema.

=item Values against maxlength attributes.

Values violating of maxlength are blocked.

=item HTML5 validation attributes

HTML5 supports some validation attributes such as [required], [pattern=*],
[type=number], [min=*], [max=*]. The plugin detects them and block violations.

=item CSRF

This also detects CSRF.

=back

=head2 CLASS METHODS

=head3 inject

Generates a schema strings of form structure for each forms in mojo response
and inject them into itself.

    my $injected = inject($html, $charset,
                                ['/path1', '/path2'], $token_key, $session_id);

=head1 AUTHOR

Sugama Keita, E<lt>sugama@jamadam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) Sugama Keita.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
