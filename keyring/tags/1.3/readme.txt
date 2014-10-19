=== Keyring ===

Contributors: beaulebens, mdawaffe, jshreve, automattic
Tags: authentication, security, oauth, http basic, key, token, authorization, delicious, facebook, flickr, foursquare, google contacts, instagram, linkedin, tumblr, twitter, yahoo
Requires at least: 3.3
Tested up to: 3.5
Stable Tag: 1.3

An authentication framework that handles authorization with external web services.

== Description ==

See the [Keyring Developer's Guide](http://dentedreality.com.au/projects/wp-keyring/) for more details.

Keyring provides a very hookable, completely customizable framework for connecting your WordPress to an external service. It takes care of all the heavy lifting when making authenticated requests, so all you need to do is implement cool features and not worry about these tricky bits.

Out of the box, Keyring currently comes with base Service definitions for webservices which use:

* HTTP Basic
* OAuth1
* OAuth2

And includes an example service implementation (services/extended/example.php) plus specific definitions for:

* [Delicious](http://delicious.com/)
* [Facebook](http://facebook.com/)
* [Flickr](http://flickr.com/)
* [Foursquare](http://foursquare.com/)
* [Google Contacts](http://google.com/)
* [Instagram](http://instagram.com/)
* [Instapaper](http://instapaper.com/)
* [LinkedIn](http://linkedin.com/)
* [RunKeeper](http://runkeeper.com/)
* [TripIt](http://tripit.com/)
* [Tumblr](http://tumblr.com/)
* [Twitter](http://twitter.com/)
* [Yahoo! Updates](http://yahoo.com/)

You can very easily write your own Service definitions and then use all the power of Keyring to hook into that authentication flow. See the [Keyring Developer's Guide](http://dentedreality.com.au/projects/wp-keyring/) for more details.


== Installation ==

1. Install Keyring either via the WordPress.org plugin directory, or by uploading the files to your server
2. Activate Keyring in Plugins > Installed Plugins
3. Go to Tools > Keyring to start setting up Services

== Frequently Asked Questions ==

= Will Keyring work on my WordPress? =

Keyring requires PHP 5.3+ to work, because it makes use of some modern features in PHP like late static binding and abstract classes. Other than that, as long as you meet the minimum required WP version, you should be OK to get started. If you get a cryptic "T_PAAMAYIM_NEKUDOTAYIM" error, you need to upgrade to PHP 5.3+.

Your webserver will also need to be able to make outbound HTTPS requests for some operations with some services to work correctly.

= How do I configure Services? =

Most services within Keyring require some sort of API key/secret before you can connect to them.

1. Go to Tools > Keyring > Add New
2. Click 'Manage' next to one of the services
3. Enter your API details (you will need to get those from the specific service)
4. Click 'Save Changes'
5. Now you should be able to create a new connection to that service

= How do I connect to 'x' service? =

1. Go to Tools > Keyring > Add New
2. Click the name of the service
3. Follow through the authentication prompts to connect
4. You should now be connected, and your connection details should be listed on the Keyring admin page (which you will be redirected to once authentication is complete)

= Now what? =

Keyring just provides a framework for handling connections to external services. You need to download another plugin which makes use of Keyring to do anything useful (e.g. an importer or content-syncing plugin).

= How does Keyring store tokens? =

* By default, on a single-site install, Keyring stores tokens in your wp_posts table with a custom post type of 'keyring_token'
* Coming soon, Keyring will store tokens for a multi-site install in a specified blog/site's wp_posts (so you can set a single site aside for just token storage if you like)
* Keyring provides a framework for you to write your own token storage engine (see store.php and includes/stores/).

= How do I add to the list of services Keyring can connect to? =

Add files to includes/services/extended/ that either implement one of the includes/services/core/ service foundations, or start from scratch. Follow one of the existing service definitions for a template, and see service.php in the root of Keyring for some detail on methods you need to define, and optional ones that might make your life easier.

== Changelog ==
= 1.3 =
* Added Service definitions for Instapaper (paid account required) and TripIt
* Improved access and request token filters
* Specify request token in token query for custom storage engines that don't use globally-unique ids
* Pass request token to verification of access tokens
* Make Keyring::init() be callable after init (it will trigger everything it needs automatically)
* Changed admin UI to use ListTable

= 1.2 =
* WARNING: BREAKING CHANGES
* Huge overhaul of codebase to support Request tokens, passing reference via 'state' param (BREAKING)
* Shuffled around how tokens are managed so that more places explicitly expect a Keyring_Token (BREAKING)
* Force serialization of stored tokens when using SingleStore (BREAKING)
* Big cleanup/changes to how token storage works, and how Keyring_Store looks (BREAKING)
* Standardized handling of meta with tokens (BREAKING)
* Added RunKeeper Service definition
* Added a bunch of filters and tried to standardize them everywhere
* Improve some nonce checking
* Improved debugging information for different service types
* Introduced app_ids for services that support/require them
* Removed all wp_die()s in favor of Keyring::error(); exit;
* Introduced test_connection() methods, props pento
* Whitespace/alignment cleanup
* Switched to using stable-tagging system in the WP.org repo

= 1.1 =
* First tagged version