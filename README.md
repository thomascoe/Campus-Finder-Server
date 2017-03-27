# Campus-Finder-Server
Gatech Campus Finder

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

## References
* http://mojolicious.org/perldoc/Mojolicious/Guides/Tutorial
* https://github.com/kraih/mojo
* https://github.com/oliwer/mango
* https://github.com/tempire/mojolicious-plugin-basicauth
