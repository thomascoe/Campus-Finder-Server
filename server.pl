#!/usr/bin/env perl
use strict;
use warnings;

use Mojolicious::Lite;
use Mango;
plugin 'basic_auth';

# Database connection
my $uri = 'mongodb://127.0.0.1:27017/test';
helper mango => sub { state $m = Mango->new($uri) };

get '/' => {text => 'Campus Finder'};


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
