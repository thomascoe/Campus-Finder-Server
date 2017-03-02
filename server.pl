#!/usr/bin/env perl
use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::JSON qw(decode_json encode_json);
use Mango;
plugin 'basic_auth';

# Database connection
my $uri = 'mongodb://127.0.0.1:27017/test';
helper mango => sub { state $m = Mango->new($uri) };

#get '/' => {text => 'Campus Finder'};

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
            my $collection = $c->mango->db->collection('user');
            my $doc = $collection->find_one({username => $username});

            # Verify Password
            # TODO: implement hashing
            if (not defined $doc or $password ne $doc->{password}) {
                $c->respond_to(any => { json => {error => 'Invalid Credentials'},
                                        status => 401});
                return;
            }

            # Check if Email is Verified
            if ($doc->{emailverstat} ne 'verified') {
                $c->respond_to(any => { json => {error => 'Awaiting Email Verification'},
                                        status => 403});
                return;
            }

            # Generate token for user
            #TODO: Generate real token
            my $token = 'abcdef123';
            $c->respond_to(any => { json => {token => $token},
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

            # Mongo Collection
            my $collection = $c->mango->db->collection('user');

            # Check if user already exists
            my $doc1 = $collection->find_one({username => $username});
            my $doc2 = $collection->find_one({email => $email});
            if (defined $doc1 or defined $doc2) {
                $c->respond_to(any => { json => {error => 'User Already Exists'},
                                        status => 409});
                return;
            }

            #TODO: Check if strong password
            if (undef) {
                $c->respond_to(any => { json => {error => 'Weak Password'},
                                        status => 400});
                return;
            }

            #TODO: Hash/salt password
            # Insert user into DB
            my $oid = $collection->insert({
                username => $username,
                email => $email,
                emailverstat => 'unverified',
                password => $password,
                radius => 1
            });

            # Send response
            $c->respond_to(any => { json => {userid => $oid},
                                    status => 200});
        };
    };
};







# Everything in this group will require authentication
group {
    under '/auth' => sub {
        my $c = shift;
        return $c->basic_auth( realm => sub {
            my $user = shift;
            my $pass = shift;
            #TODO: Store user/pass instead of hardcode
            if ($user eq 'username' && $pass eq '123') {
                return 1;
            }
        });
    };

    # Store user
    get '/insert/users/:name' => sub {
        my $c   = shift;

        # Get parameters from URL
        my $name = $c->param('name');
        my $age = $c->param('age');

        # Mongo DB
        my $collection = $c->mango->db->collection('user');

        # Insert into DB
        my $oid = $collection->insert({
            name => $name,
            age => $age
        });

        # Render text
        $c->render(text => "Object $oid created in db");
    };

    get '/get/users' => sub {
        my $c   = shift;

        # Mongo DB
        my $collection = $c->mango->db->collection('user');

        my $docs = $collection->find->all();

        $c->render(json => $docs);
    };

    # Get user
    get '/get/users/:name' => sub {
        my $c   = shift;

        # Get parameters from URL
        my $name = $c->param('name');

        # Mongo DB
        my $collection = $c->mango->db->collection('user');

        # Retrieve user from DB
        my $doc = $collection->find_one({name => $name});

        # Render result
        $c->render(json => $doc);
    };

};

app->start;
