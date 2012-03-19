=== Keyring ===

Contributors: beaulebens
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

== Changelog ==

= trunk =
* Initial upload (unreleased)
