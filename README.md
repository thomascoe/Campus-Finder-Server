# Campus-Finder-Server
<img src="logo.png" width="300">

Gatech Campus Finder is a crowdsourced platform which allows users to submit, comment, and vote on different points of interest around the Georgia Tech campus. Example usage includes documenting and sharing locations such as student-accessible printers, bathrooms, vending machines, and visitor parking. This server is built in Perl with a RESTful API which enables multiple clients to access the data provided.

## Dependencies
* Perl
* MongoDB
    * (mongod running on local server)
* Mojolicious
    * cpanm Mojolicious::Lite
* Mango
    * cpanm Mango
* Mojolicious::Plugin::BasicAuth
    * cpanm Mojolicious::Plugin::BasicAuth
* Crypt::SaltedHash
    * cpanm Crypt::SaltedHash

## Running
* Basic
    * `./server.pl daemon -l http://*:8080`
* Alternatively, you can run with the morbo development server, which reloads application after each change
    * `morbo -l http://*:8080 server.pl`
* To run in background disconnected from terminal
    * `nohup ./server.pl daemon -l http://*:8080&`

## API Reference

### Unauthenticated
* POST /v1/auth/login
    * Required params: username, password
    * Response: username, token
    * Error codes: 400 (missing parameter), 401 (invalid credentials), 403 (account unverified)
* POST /v1/auth/register
    * Required params: username, password, email
    * Response: {}
    * Error codes: 400 (missing parameter, insecure password), 409 (user already exists)
* POST /v1/auth/resetpass
    * Required params: email
    * Response: {}
    * Error codes: 400 (invalid user)
* POST /v1/auth/resendverification
    * Required params: email
    * Response: {}
    * Error codes: 400 (invalid user, user already verified)

### Authenticated
#### HTTP Basic Auth required. Credentials are username and token (obtained from /v1/auth/login)
* POST /v1/auth/updatepass
    * Required params: newpass
    * Response: {}
    * Error codes: 400 (missing parameter, insecure password)
* POST /v1/auth/logout
    * Response: {}
* GET /v1/types
    * Response: [{"type"}, ...]
* GET /v1/locations
    * Response: [{"id", "name", "type", "latitude", "longitude"}, ...]
* POST /v1/locations
    * Request body: name, type, description, latitude, longitude
    * Response: {location}
    * Error codes: 400 (missing parameter, invalid type)
* GET /v1/locations/:locationid
    * Response: [{location}, ...]
* POST /v1/locations/:locationid/vote
    * Required params: vote
    * Response: {}
    * Error codes: 400 (missing parameter, invalid vote), 404 (location not found)
* GET /v1/locations/:locationid/comments
    * Response: [{comment}, ...]
    * Error codes: 404 (location not found)
* POST /v1/locations/:locationid/comments
    * Request body: comment text
    * Response: {}
    * Error codes: 400 (no comment body), 404 (location not found)
* DELETE /v1/locations/:locationid/comments/:commentid
    * Response: {}
    * Error codes: 403 (not owner of comment), 404 (location not found, comment not found)

## References
* http://mojolicious.org/perldoc/Mojolicious/Guides/Tutorial
* https://github.com/kraih/mojo
* https://github.com/oliwer/mango
* https://github.com/tempire/mojolicious-plugin-basicauth
