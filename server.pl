#!/usr/bin/env perl
use strict;
use warnings;

use Time::Piece;
use Crypt::SaltedHash;
use Mojolicious::Lite;
use Mojo::JSON qw(decode_json encode_json);
use Mango;
plugin 'basic_auth';

sub send_email {
    my ($to, $from, $subject, $body) = @_;
    `echo "$body" | mail -s "$subject" -r "$from" $to`;
}

sub is_strong_pass {
    my ($pass) = @_;
    # TODO: Implement pass strength check
    return 1;
}

sub gen_hash {
    my ($var) = @_;
    my $csh = Crypt::SaltedHash->new(algorithm => 'SHA-256');
    $csh->add($var);
    return $csh->generate;
}

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

            # Check if Email is Verified
            if ($doc->{emailverstat} ne 'verified') {
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

            if (not is_strong_pass($password)) {
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
            my $saltedhash = gen_hash($password);

            # Generate verification code
            my $code = unpack 'h32', `head -c 16 /dev/urandom`;

            # Insert user into DB
            my $oid = $users->insert({
                username => $username,
                email => $email,
                emailverstat => 'unverified',
                emailvercode => $code,
                password => $saltedhash,
                radius => 1
            });

            # Send email to new user with confirmation link
            my $link = "https://thomascoe.com/campus-finder/v1/auth/verify?email=$email&code=$code";
            my $from = 'campusfinder@thomascoe.com';
            my $subject = 'Welcome to Campus Finder!';
            my $body = "Please verify your email to activate your account\n$link";
            send_email($email, $from, $subject, $body);

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

            #TODO: Send email with temp password
            $c->respond_to(any => { json => {}, status => 200});
        };

        get '/verify' => sub {
            my $c = shift;
            my $email = $c->param('email');
            my $code = $c->param('code');

            # Lookup user to get verification status and code
            my $users = $c->mango->db->collection('user');
            my $doc = $users->find_one({email => $email});

            # Error handling
            if (not defined $doc) {
                $c->respond_to(any => { text => "Error: User Not Found", status => 400});
                return;
            } elsif ($doc->{emailverstat} eq 'verified') {
                $c->respond_to(any => { text => "User already verified", status => 400});
                return;
            } elsif ($doc->{emailvercode} ne $code) {
                $c->respond_to(any => { text => "Error: Verification code incorrect", status => 400});
                return;
            }

            # Mark user as verified
            $users->update($doc->{_id}, {'$set' => {emailverstat => 'verified'}});
            $c->respond_to(any => { text => "Verification successful!", status => 200});
        }
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

        post '/auth/updatepass' => sub {
            my $c = shift;
            my ($user, $pass) = split /:/, $c->req->url->to_abs->userinfo;
            my $newpass = $c->param('newpass');

            if (not defined $newpass) {
                $c->respond_to(any => { json => {error => 'Bad Request'},
                                        status => 400});
                return;
            }

            # Check password strength
            if (not is_strong_pass($newpass)) {
                $c->respond_to(any => { json => {error => 'Weak password'},
                                        status => 400});
                return;
            }

            # Hash/salt password
            my $saltedhash = gen_hash($newpass);

            # Update DB
            my $users = $c->mango->db->collection('user');
            $users->update({username => $user}, {'$set' => {password => $saltedhash}});
            $c->respond_to(any => { json => {}, status => 200});
        };

        post '/auth/logout' => sub {
            my $c = shift;
            my ($user, $pass) = split /:/, $c->req->url->to_abs->userinfo;
            my $sessions = $c->mango->db->collection('sessions');
            $sessions->remove({username => $user, token => $pass});
            $c->respond_to(any => { json => {}, status => 200});
        };

        get '/types' => sub {
            my $c = shift;
            my $types = $c->mango->db->collection('types');
            my $docs = $types->find({}, {_id => 0})->all;
            $c->respond_to(any => { json => $docs, status => 200});
        };

        get '/locations' => sub {
            my $c = shift;
            my $locations = $c->mango->db->collection('locations');

            # TODO: Allow filter by type? maybe do client side?
            my $docs = $locations->find({}, {name => 1, type => 1, latitude => 1, longitude => 1})->all;
            $c->respond_to(any => { json => $docs, status => 200});
        };

        post '/locations' => sub {
            my $c = shift;
            my ($user, $pass) = split /:/, $c->req->url->to_abs->userinfo;
            my $loc = $c->req->json;
            if (not defined $loc->{name}
                    or not defined $loc->{type}
                    or not defined $loc->{description}
                    or not defined $loc->{latitude}
                    or not defined $loc->{longitude}) {
                $c->respond_to(any => { json => {error => 'Missing Required Params (name, type, descriptions, latitude, longitude)'},
                                        status => 400});
                return;
            }

            # Verify type is valid
            my $types = $c->mango->db->collection('types');
            if (not defined $types->find_one({type => $loc->{type}})) {
                $c->respond_to(any => { json => {error => 'Invalid type'}, status => 400});
                return;
            }

            # Set extra params
            $loc->{username} = $user;
            $loc->{timestamp} = gmtime->datetime . 'Z';
            $loc->{upvotes} = 0;
            $loc->{downvotes} = 0;

            # Insert into database
            my $locations = $c->mango->db->collection('locations');
            $locations->insert($loc);

            $c->respond_to(any => { json => $loc, status => 200});
        };

        get '/locations/:locationid' => sub {
            my $c = shift;
            my ($user, $pass) = split /:/, $c->req->url->to_abs->userinfo;

            # Look up location
            my $locid = $c->param('locationid');
            my $oid = Mango::BSON::ObjectID->new($locid);
            my $locations = $c->mango->db->collection('locations');
            my $doc = $locations->find_one({_id => $oid});
            if (not defined $doc) {
                $c->respond_to(any => { json => {error => "Location not found"}, status => 404});
                return;
            }

            # Look up this user's vote
            my $votes = $c->mango->db->collection('votes');
            my $votedoc = $votes->find_one({locationid => $locid, username => $user});
            my $vote = 0;
            if (defined $votedoc) {
                $vote = $votedoc->{vote};
            }
            $doc->{myvote} = $vote;
            $c->respond_to(any => { json => $doc, status => 200});
        };

        post '/locations/:locationid/vote' => sub {
            my $c = shift;
            my ($user, $pass) = split /:/, $c->req->url->to_abs->userinfo;
            my $vote = $c->param('vote') + 0;
            my $locid = $c->param('locationid');

            # Verify vote
            if ((not defined $vote) or ($vote ne 1 and $vote ne 0 and $vote ne -1)) {
                $c->respond_to(any => { json => {error => "Invalid vote"}, status => 400});
                return;
            }

            # Look up location
            my $oid = Mango::BSON::ObjectID->new($locid);
            my $locations = $c->mango->db->collection('locations');
            my $doc = $locations->find_one({_id => $oid});
            if (not defined $doc) {
                $c->respond_to(any => { json => {error => "Location not found"}, status => 404});
                return;
            }

            # Look up this user's vote
            my $votes = $c->mango->db->collection('votes');
            my $votedoc = $votes->find_one({locationid => $locid, username => $user});
            my $oldvote = 0;
            if (defined $votedoc) {
                $oldvote = $votedoc->{vote};
            }

            # Calculate the upvote/downvote differentials
            my $upvotes = 0;
            my $downvotes = 0;
            if ($vote eq 0) {
                if ($oldvote eq 1) {
                    $upvotes = -1;
                } elsif ($oldvote eq -1) {
                    $downvotes = -1;
                }
            } elsif ($vote eq 1) {
                if ($oldvote eq -1) {
                    $upvotes = 1;
                    $downvotes = -1;
                } elsif ($oldvote eq 0) {
                    $upvotes = 1;
                }
            } elsif ($vote eq -1) {
                if ($oldvote eq 1) {
                    $upvotes = -1;
                    $downvotes = 1;
                } elsif ($oldvote eq 0) {
                    $downvotes = 1;
                }
            }

            # Update the DB
            $locations->update({_id => $oid}, {'$inc' => {upvotes => $upvotes, downvotes => $downvotes}});
            $votes->update({locationid => $locid, username => $user}, {'$set' => {vote => $vote}}, {upsert => 1});
            $c->respond_to(any => { json => {}, status => 200});
        };
    };
};



app->start;
