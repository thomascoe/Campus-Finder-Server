# Campus-Finder-Server
Gatech Campus Finder

## Dependencies
* Perl
* MongoDB
    * (mongod running on local server)
* Mojolicious
    * (from CPAN)
* Mango
    * (from CPAN)
* Mojolicous::Plugin::BasicAuth
    * (from CPAN)

## Running
* Basic
    * `./server.pl daemon -l http://*:8080`
* Alternatively, you can run with the morbo development server, which reloads application after each change
    * `morbo server.pl`

## References
* http://mojolicious.org/perldoc/Mojolicious/Guides/Tutorial
* https://github.com/kraih/mojo
* https://github.com/oliwer/mango
* https://github.com/tempire/mojolicious-plugin-basicauth
