=== Keyring ===

Contributors: beaulebens, mdawaffe, jshreve, automattic
Tags: authentication, security, oauth, http basic, key, token, authorization, twitter, facebook, delicious, foursquare, flickr
Requires at least: 3.3
Tested up to: 3.3
Stable Tag: 1.0

An authentication framework that handles authorization with external web services.

== Description ==

**NOTE: This is "pre-release" software! Don't use it on production/as the foundation for anything serious yet. APIs etc are likely to change still.**

Keyring provides a very hookable, completely customizable framework for connecting your WordPress to an external service. It takes care of all the heavy lifting when making authenticated requests, so all you need to do is implement cool features and not worry about these tricky bits.

Out of the box, Keyring currently comes with base Service definitions for webservices which use:

* OAuth1 and OAuth2
* HTTP Basic

And specific extensions for connecting to:

* [Delicious](http://delicious.com/)
* [Facebook](http://facebook.com/)
* [Flickr](http://flickr.com/)
* [Foursquare](http://foursquare.com/)
* [Twitter](http://twitter.com/)

You can very easily write your own Service definitions and then use all the power of Keyring to hook into that authentication flow (tutorial/code samples coming soon).

== Installation ==

1. Install Keyring either via the WordPress.org plugin directory, or by uploading the files to your server
2. Activate Keyring in Plugins > Installed Plugins
3. Go to Tools > Keyring to start setting up Services

== Frequently Asked Questions ==

= Will Keyring work on my WordPress? =

Keyring requires PHP 5.3+ to work, because it makes use of some modern features in PHP like late static binding and abstract classes. Other than that, as long as you meet the minimum required WP version, you should be OK to get started.

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
