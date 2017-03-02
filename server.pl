#!/usr/bin/env perl
use strict;
use warnings;

use Time::Piece;
use Crypt::SaltedHash;
use Mojolicious::Lite;
use Mojo::JSON qw(decode_json encode_json);
use Mango;
plugin 'basic_auth';

# Database connection
my $uri = 'mongodb://127.0.0.1:27017/test';
helper mango => sub { state $m = Mango->new($uri) };

get '/' => {text => 'Gatech Campus Finder'};

group {
    under '/v1';

    group {
        under '/auth';

        # User Login, returns a token for user to use as password
        post '/login' => sub {
            # Get parameters
            my $c = shift;
            my $username = $c->param('username');
            my $password = $c->param('password');
            if (not defined $username or not defined $password) {
                $c->respond_to(any => { json => {error => 'Bad Request'},
                                        status => 400});
                return;
            }

            # Lookup user in DB
            my $users = $c->mango->db->collection('user');
            my $doc = $users->find_one({username => $username});

            # Verify Password
            my $validpw = Crypt::SaltedHash->validate($doc->{password}, $password);
            if (not defined $doc or not $validpw) {
                $c->respond_to(any => { json => {error => 'Invalid Credentials'},
                                        status => 401});
                return;
            }

            #$c->respond_to(any => { json => $doc, status => 200});
            #return;

            # Check if Email is Verified
            # TODO: Remove 'undef and'
            if (undef and $doc->{emailverstat} ne 'verified') {
                $c->respond_to(any => { json => {error => 'Awaiting Email Verification'},
                                        status => 403});
                return;
            }

            # Generate token for user
            my $token = unpack 'h32', `head -c 16 /dev/urandom`;
            my $timestring = gmtime->datetime . 'Z';

            # Store session in db
            my $sessions = $c->mango->db->collection('sessions');
            my $oid = $sessions->insert({
                username => $username,
                token => $token,
                timestamp => $timestring
            });

            # Send response to client
            $c->respond_to(any => { json => {username => $username, token => $token},
                                    status => 200});
        };

        # User register
        post '/register' => sub {
            # Get Parameters
            my $c = shift;
            my $username = $c->param('username');
            my $email = $c->param('email');
            my $password = $c->param('password');
            if (not defined $username or not defined $email or not defined $password) {
                $c->respond_to(any => { json => {error => 'Bad Request'},
                                        status => 400});
                return;
            }

            #TODO: Check if strong password
            if (undef) {
                $c->respond_to(any => { json => {error => 'Weak Password'},
                                        status => 400});
                return;
            }

            # Check if user already exists
            my $users = $c->mango->db->collection('user');
            my $doc1 = $users->find_one({username => $username});
            my $doc2 = $users->find_one({email => $email});
            #my $docs = $users->find->all();
            if (defined $doc1 or defined $doc2) {
                $c->respond_to(any => { json => {error => 'User Already Exists'},
                                        status => 409});
                return;
            }

            # Hash/salt password
            my $csh = Crypt::SaltedHash->new(algorithm => 'SHA-256');
            $csh->add($password);
            my $saltedhash = $csh->generate;

            # Insert user into DB
            my $oid = $users->insert({
                username => $username,
                email => $email,
                emailverstat => 'unverified',
                password => $saltedhash,
                radius => 1
            });

            #TODO: Send email to new user with confirmation link

            # Send response
            $c->respond_to(any => { json => {userid => $oid},
                                    status => 200});
        };

        post '/resetpass' => sub {
            my $c = shift;
            my $email = $c->param('email');
            my $users = $c->mango->db->collection('user');
            my $doc = $users->find_one({email => $email});
            if (not defined $doc) {
                $c->respond_to(any => { json => {error => 'User Not Found'},
                                        status => 400});
                return;
            }

            #TODO: Send email with password reset link
            $c->respond_to(any => { json => {}, status => 200});
        };
    };

    # Everything in this group will require authentication
    group {
        under sub {
            my $c = shift;
            return $c->basic_auth( realm => sub {
                my $user = shift;
                my $token = shift;

                # Lookup session in the db
                my $sessions = $c->mango->db->collection('sessions');
                my $doc = $sessions->find_one({username => $user, token => $token});
                if (defined $doc) {
                    return 1;
                }
            });
        };

        get '/types' => sub {
            my $c = shift;
            my ($user, $pass) = split /:/, $c->req->url->to_abs->userinfo;
            $c->respond_to(any => { json => {"status" => "success"},
                                    status => 200});
        };
    };
};



app->start;
