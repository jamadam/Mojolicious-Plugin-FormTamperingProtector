package Mojolicious::Plugin::FormValidatorLazy;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
our $VERSION = '0.01';
use Data::Dumper;
use Mojo::JSON;
use Mojo::Util qw{encode decode xml_escape hmac_sha1_sum secure_compare
                                                        b64_decode b64_encode};

my $TERM_ACTION             = 0;
my $TERM_SCHEMA             = 1;
my $TERM_PROPERTIES         = 2;  # 'properties'
my $TERM_REQUIRED           = 3;  # 'required'
my $TERM_MAXLENGTH          = 4;  # 'maxLength'
my $TERM_MIN_LENGTH         = 5;  # 'minLength'
my $TERM_OPTIONS            = 6;  # 'options'
my $TERM_PATTERN            = 7;  # 'pattern'
my $TERM_MIN                = 8;  # 'maximam'
my $TERM_MAX                = 9;  # 'minimum'
my $TERM_TYPE               = 10; # 'type'
my $TERM_ADD_PROPS          = 11; # 'additionalProperties'
my $TERM_NUMBER             = 12; # 'number'

my $json = Mojo::JSON->new;

### ---
### register
### ---
sub register {
    my ($self, $app, $opt) = @_;
    
    my $schema_key = $opt->{namespace}. "-schema";
    my $sess_key = $opt->{namespace}. '-sessid';
    
    my $actions = ref $opt->{action} ? $opt->{action} : [$opt->{action}];
    
    $app->hook(before_dispatch => sub {
        my $c = shift;
        my $req = $c->req;
        
        if ($req->method eq 'POST' && grep {$_ eq $req->url->path} @$actions) {
            
            my $token = $req->param($schema_key);
            $req->params->remove($schema_key);
            
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
            
            $c->res->body(inject_schema(
                $c->res->body,
                $actions,
                $schema_key,
                $sessid,
                $c->res->content->charset,
            ));
        }
    });
}

sub inject_schema {
    my ($body, $actions, $token_key, $sessid, $charset) = @_;
    
    my $dom = Mojo::DOM->new($charset ? decode($charset, $body) : $body);
    
    for my $action (@$actions) {
        $dom->find(qq{form[action="$action"][method="post"]})->each(sub {
            my $form    = shift;
            my $wrapper = sign(serialize({
                $TERM_ACTION    => $form->attr('action'),
                $TERM_SCHEMA    => extract_schema($form, $charset),
            }), $sessid);
            
            $form->append_content(sprintf(<<"EOF", $token_key, xml_escape $wrapper));
<div style="display:none">
    <input type="hidden" name="%s" value="%s">
</div>
EOF
        });
    }
    
    return encode($charset, $dom->to_xml);
}

sub extract_schema {
    my ($form, $charset) = @_;
    my $props   = {};
    my @required;
    
    if (! ref $form) {
        $form = Mojo::DOM->new($charset ? decode($charset, $form) : $form);
    }
    
    $form->find("*[name]")->each(sub {
        my $tag = shift;
        my $type = $tag->attr('type');
        my $name = $tag->attr('name');
        $props->{$name} ||= {};
        
        if (grep {$_ eq $type} qw{hidden checkbox radio submit image}) {
            push(@{$props->{$name}->{$TERM_OPTIONS}}, $tag->attr('value'));
        }
        
        if ($tag->type eq 'select') {
            $tag->find('option')->each(sub {
                push(@{$props->{$name}->{$TERM_OPTIONS}}, shift->attr('value'));
            });
        }
        
        if ($type eq 'number') {
            $props->{$name}->{$TERM_TYPE} = $TERM_NUMBER;
            if (my $val = $tag->attr->{min}) {
                $props->{$name}->{$TERM_MIN} = $val;
            }
            if (my $val = $tag->attr->{max}) {
                $props->{$name}->{$TERM_MAX} = $val;
            }
        }
        
        if (! exists $tag->attr->{disabled}) {
            if ($type ne 'submit' && $type ne 'image' && $type ne 'checkbox' &&
                        ($type ne 'radio' || exists $tag->attr->{checked})) {
                $props->{$name}->{$TERM_REQUIRED} = Mojo::JSON->true;
            }
        }
            
        if (exists $tag->attr->{maxlength}) {
            $props->{$name}->{$TERM_MAXLENGTH} = $tag->attr->{maxlength} || 0;
        }
        
        if (exists $tag->attr->{required}) {
            $props->{$name}->{$TERM_MIN_LENGTH} = 1;
        }
        
        if (exists $tag->attr->{pattern}) {
            $props->{$name}->{$TERM_PATTERN} = $tag->attr->{pattern};
        }
    });
    
    return {
        $TERM_PROPERTIES => $props,
        $TERM_ADD_PROPS => Mojo::JSON->false,
    };
}

sub validate {
    my ($req, $encoded_schema, $sessid) = @_;
    
    if (! $sessid) {
        return 'CSRF is detected';
    }
    
    my $params = $req->params;
    my $req_path = $req->url->path;

    if (! $encoded_schema) {
        return 'Schema is not found';
    }
    
    my $wrapper = deserialize(unsign($encoded_schema, $sessid));
    
    if (!$wrapper) {
        return 'Schema has been tampered';
    }
    
    my $props = $wrapper->{$TERM_SCHEMA}->{$TERM_PROPERTIES};
    
    if ($req_path ne $wrapper->{$TERM_ACTION}) {
        return "Action attribute has been tampered";
    }
    
    if (! $wrapper->{$TERM_SCHEMA}->{$TERM_ADD_PROPS}) {
        for my $name ($params->param) {
            if (! $props->{$name}) {
                return "Field $name is injected";
            }
        }
    }
    
    for my $name (keys %$props) {
        
        my @params = $params->param($name);
        
        if (($props->{$name}->{$TERM_REQUIRED} || '') eq Mojo::JSON->true) {
            if (! scalar @params) {
                return "Field $name is required";
            }
        }
        
        if (my $allowed = $props->{$name}->{$TERM_OPTIONS}) {
            for my $given (@params) {
                if (! grep {$_ eq $given} @$allowed) {
                    return "Field $name has been tampered";
                }
            }
        }
        if (exists $props->{$name}->{$TERM_MAXLENGTH}) {
            for my $given (@params) {
                if (length($given) > $props->{$name}->{$TERM_MAXLENGTH}) {
                    return "Field $name is too long";
                }
            }
        }
        if (defined $props->{$name}->{$TERM_MIN_LENGTH}) {
            for my $given (@params) {
                if (length($given) < $props->{$name}->{$TERM_MIN_LENGTH}) {
                    return "Field $name cannot be empty";
                }
            }
        }
        if (my $pattern = $props->{$name}->{$TERM_PATTERN}) {
            for my $given (@params) {
                if ($given !~ /\A$pattern\Z/) {
                    return "Field $name not match pattern";
                }
            }
        }
        if (($props->{$name}->{$TERM_TYPE} || '') eq $TERM_NUMBER) {
            for my $given (@params) {
                if ($given !~ /\A[\d\+\-\.]+\Z/) {
                    return "Field $name not match pattern";
                }
                if (my $min = $props->{$name}->{$TERM_MIN}) {
                    if ($given < $min) {
                        return "Field $name too low";
                    }
                }
                if (my $max = $props->{$name}->{$TERM_MAX}) {
                    if ($given > $max) {
                        return "Field $name too great";
                    }
                }
            }
        }
    }
    return;
}

sub serialize {
    return b64_encode($json->encode(shift), '');
}

sub deserialize {
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

=head3 extract_schema

    my $schema = extract_schema($form_in_strig, $charset)
    my $schema = extract_schema($form_in_mojo_dom)

Generates a schema out of form string or Mojo::DOM instance. It returns
schema in hashref consists of JSON-schema-like properties.

=head3 inject_schema

Generates a schema strings of form structure for each forms in mojo response
and inject them into itself.

    my $html = inject_schema($res, $charset,
                                ['/path1', '/path2'], $token_key, $session_id);

=head3 validate

Validates form data of given mojo request by given schema.

    my $error = validate($req, $schema, $session_id);

=head1 AUTHOR

Sugama Keita, E<lt>sugama@jamadam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) Sugama Keita.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
