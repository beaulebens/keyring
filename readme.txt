=== Keyring ===

Contributors: beaulebens, mdawaffe, jshreve, jkudish, automattic
Tags: authentication, security, oauth, http basic, authorization, facebook, foursquare, instagram, twitter, google
Requires at least: 4.0
Tested up to: 5.2.1
Stable Tag: 2.0

An authentication framework that handles authorization/communication with most popular web services.

== Description ==

**See the [Keyring Developer's Guide](http://dentedreality.com.au/projects/wp-keyring/) for more details.**

Keyring provides a very hookable, completely customizable framework for connecting your WordPress to an external service. It takes care of all the heavy lifting when making authenticated requests, so all you need to do is implement cool features and not worry about these tricky bits.

Out of the box, Keyring currently comes with base Service definitions for:

* HTTP Basic,
* OAuth1, and
* OAuth2.

And includes ready-to-use definitions for:

* [500px](https://500px.com/)
* [Delicious](https://delicious.com/)
* [Eventbrite](https://eventbrite.com/)
* [Facebook](https://facebook.com/)
* [Fitbit](https://fitbit.com/)
* [Flickr](https://flickr.com/)
* [Foursquare](https://foursquare.com/)
* [Google Analytics](https://www.google.com/analytics/)
* [Google Contacts](https://www.google.com/contacts/)
* [Google Mail](https://www.google.com/mail/)
* [Instagram](https://instagram.com/)
* [Instapaper](https://instapaper.com/)
* [Jetpack](https://jetpack.com/)/[WordPress.com](https://wordpress.com/)
* [LinkedIn](https://linkedin.com/)
* [Moves](https://moves-app.com/)
* [Nest](https://nest.com/)
* [Pinterest](https://pinterest.com/)
* [RunKeeper](https://runkeeper.com/)
* [Strava](https://strava.com/)
* [TripIt](https://tripit.com/)
* [Tumblr](https://tumblr.com/)
* [Twitter](https://twitter.com/)
* [Yahoo! Updates](https://yahoo.com/)
* [YouTube](https://youtube.com/)

You can very easily write your own Service definitions and then use all the power of Keyring to hook into that authentication flow. See the [Keyring Developer's Guide](http://dentedreality.com.au/projects/wp-keyring/) for more details.

Contributions are welcome via [Github pull request](https://github.com/beaulebens/keyring).


== Installation ==

1. Install Keyring either via the WordPress.org plugin directory, or by uploading the files to your server
2. Activate Keyring in Plugins > Installed Plugins
3. Go to Tools > Keyring > Add New and you will be prompted to configure services before making user-specific connections to them

== Frequently Asked Questions ==

= How Do I Use Keyring in my Plugin? =

Check out the [Keyring Developer's Guide](http://dentedreality.com.au/projects/wp-keyring/).

See [Keyring Social Importers](http://wordpress.org/plugins/keyring-social-importers/) for an example. You can also extend Keyring Service classes directly, rather than attaching the service as a property to an object (like the Importers do).

= Will Keyring work on my WordPress? =

Keyring **requires PHP 5.3+ to work**, because it makes use of some modern features in PHP like late static binding and abstract classes. Other than that, as long as you meet the minimum required WP version, you should be OK to get started. If you get a cryptic "T_PAAMAYIM_NEKUDOTAYIM" error, you need to upgrade to PHP 5.3+. If you get an error about "Parse error: syntax error, unexpected T_FUNCTION in .../wp-content/plugins/keyring/keyring.php on line 50" you also need to upgrade PHP.

Your webserver will also need to be able to make outbound HTTPS requests for some operations with some services to work correctly.

= How do I configure Services? =

Most services within Keyring require some sort of API key/secret before you can connect to them.

1. Go to Tools > Keyring > Add New.
2. Click the name of a service in the bottom section, or 'Manage' next to one of the services in the top section.
3. Enter your API details (you will need to get those from the specific service, most config screens provide links/details on how to set them up).
4. Click 'Save Changes'.
5. Now you should be able to create a new connection to that service from the "Add New" screen.

= How do I connect to 'x' service? =

1. Go to Tools > Keyring > Add New.
2. Click the name of the service in the top section (if it's in the bottom section, then that service has not been configured for API access yet, see above).
3. Follow through any authentication prompts to connect.
4. You should now be connected, and your connection details should be listed on the Keyring admin page (which you will be redirected to once authentication is complete).

= Now what? =

Keyring just provides a framework for handling connections to external services. You need to download another plugin which makes use of Keyring to do anything useful (e.g. an importer or content-syncing plugin).

= How does Keyring store tokens? =

* By default, on a single-site install, Keyring stores tokens in your wp_posts table with a custom post type of 'keyring_token'
* Coming soon, Keyring will store tokens for a multi-site install in a specified blog/site's wp_posts (so you can set a single site aside for just token storage if you like)
* Keyring provides a framework for you to write your own token storage engine (see store.php and includes/stores/).

= How do I add to the list of services Keyring can connect to? =

Add files to includes/services/extended/ that either implement one of the includes/services/core/ service foundations, or start from scratch. Follow one of the existing service definitions for a template, and see service.php in the root of Keyring for some detail on methods you need to define, and optional ones that might make your life easier.

== Changelog ==

=  =
* Enhancement: `fetch_profile_picture` method added to Twitter service. Props @glendaviesnz.
* Enhancement BREAKING: LinkedIn now uses OAuth2. Props @glendaviesnz.
* Enhancement: Added a GitHub Service definition, props @alperakgun.
* Enhancement: Added a Google Drive Service definition, props @scruffian.
* Enhancement: Trim spaces off API keys etc to avoid mistakes when copy/pasting. Props @kbrown9.
* Enhancement: Allow all 2xx response codes to be considered "Success" for all requests, for all protocols. Props @bgrgicak for the proposal.
* Enhancement: Add translator comments. Props @scruffian.
* Enhancement: Define the `self` endpoint for Tumbler, and add helper methods to retrieve user info. Props @glendaviesnz.
* Enhancement: Add a `keyring_{service}_request_scope` filter for OAuth2 services, matching the existing filter for OAuth1 services. Props @glendaviesnz.
* Enhancement: Add a `'full_response'` param to `Keyring_Service_OAuth2::request()`, which will cause the method to return the full HTTP response object. Props @glendaviesnz.
* Bugfix: Make the Google services always request a refresh token for offline access. Props @kbrown9 and @atrniv for input.
* Bugfix: Update Strava to use refresh tokens and offline access, per their new API requirements. Props @mdrovdahl for pointing it out.
* Bugfix: Update use of add_submenu_page() to comply with WP 5.3. Props @jhwwp (wp.org) for the fix.
* Bugfix: Apply the keyring_access_token filter consistently in Google Services. Props @pablinos.
* Bugfix: Use static "Cancel" URIs in UIs. Props @pgl.
* Bugfix: Remove some WordPress.com-specific code from Eventbrite.
* Bugfix: Ensure that `PUT` requests have a `Content-Length` header set. Props @glendaviesnz.

= 2.0 =
* Bugfix BREAKING: Remove invalid reference to $this in error handler. Changes number of params passed to keyring_error action.
* Bugfix BREAKING: `expires` values in tokens MUST be UNIX timestamps now.
* Enhancement BREAKING: All Google services now share a base service (0-google-base.php)
* Enhancement: Added a Pocket Service, props @roccotripaldi
* Enhancement: Added a Google Mail (Gmail) Service, props @poisa
* Enhancement: Added a YouTube Service definition, based heavily on @superbia's Google Analytics one.
* Enhancement: Add a composer.json config file (Keyring is now on Packagist at https://packagist.org/packages/beaulebens/keyring)
* Bugfix: Handle empty usernames in the Strava Service.
* Bugfix: Updated links in readme for Google Analytics and Contacts to their user-facing URLs.

= 1.9 =
* Enhancement: Added a Google Analytics Service definition, props @superbia.
* Enhancement: Added a Strava Service definition, props @mdrovdahl.
* Enhancement: Add a "Settings" link to the plugin listing if you're using the bundled Admin UI.
* Bugfix: Remove deprecated calls to `screen_icon()`.
* Bugfix: Fitbit tokens now refresh automatically.
* Bugfix: Tumblr now requires HTTPS, so update all request URLs. Props @westi.

= 1.8 =
* Enhancement: New Jetpack/WordPress.com service definition.
* Bugfix: LinkedIn scope require modification because connections were failing.
* Enhancement: Extensive linting/code cleanup, including removing some redundant code.

= 1.7.1 =
* Bugfix: Only allow users with `manage_options` to access management UIs. Props Laura Lee for disclosure.

= 1.7 =
* Enhancement: Added Pinterest Service definition.
* Enhancement: Added Nest Service definition.
* Enhancement: New filter for modifying credentials before saving (`keyring_{service}_basic_ui_save_credentials`).
* Enhancement: Update all services so that token-meta filters use a dynamic service name, making it much easier to extend existing services. Props @jjj.
* Bugfix: Use `sentence` parameter when searching for existing tokens, to avoid WordPress doing weird word-splitting. Props @dashaluna.
* Bugfix: Correct URL for Instagram to load profile details (required for a working connection). Props @dashaluna.
* Bugfix: Correct the URL for creating a Twitter app. Props @jjj.
* Bugfix: Handle avatar URLs better within the admin UI. Props @jjj.
* Bugfix: Correct URL for registering Eventbrite apps.

= 1.6.2 =
* Enhancement: New Fitbit service definition
* Enhancement: New 500px service definition, props https://github.com/petermolnar
* Enhancement: Allow filtering of POST parameters during token verification for OAuth2 via `keyring_{service}_verify_token_post_params`
* Enhancement: Allow filtering of service configuration fields, props https://github.com/justinshreve
* Enhancement: Add `test_connection()` method for all services, so that you can confirm if a token is working via the Admin UI
* Enhancement: Facebook: use new endpoints, ability to list Pages this token has access to
* Enhancement: Include token meta in admin UI, make avatars bigger
* Enhancement: Avoid fatal error on sites with the pecl OAuth library installed, props https://github.com/sanchothefat
* Enhancement: Use internal WP function to ensure querystrings are correctly encoded in OAuth2 implementation, props https://github.com/cfinke
* Enhancement: Make Keyring::error() able to record errors without wp_die()ing (optional)
* Bugfix: Actually detect responses from connection-tests properly, and report them as errors
* Bugfix: Avoid PHP notice in http-basic

= 1.6.1 =
* Enhancement: Add Eventbrite as a service, props @jkudish

= 1.6 =
* Enhancement BREAKING: Change the way the keyring_admin_url filter is applied so that it's already got all the parameters etc added to it by the time the filter happens. Makes that filter much more flexible. You probably need to add $params to your filter function, and the add_query_arg() those params onto whatever URL you're returning.
* Bugfix WARNING: Change the filters in get_credentials() to keyring_service_credentials, since keyring_credentials is in use, and slightly different
* Enhancement: Allow the token store to be filtered, for divergent implementations on a single installation, props Jamie P
* Enhancement: Allow filtering of request scope for OAuth1 services
* Enhancement: Add connection-testing to the default admin UI for most services
* Enhancement: Abstract out prepare_request() for OAuth1 service
* Bugfix: Use the correct parameters for filtering results in SingleStore, props Milan D
* Bugfix: Request correct permissions for LinkedIn, using the new filter
* Bugfix: Get Google Contacts working properly. Props Simon W for spotting 2 errors.
* Bugfix: Update authorize/authenticate URL for LinkedIn. Should move entire service to OAuth2 ideally
* Bugfix: Don't restrict the 'state' parameter to being an int only (per OAuth2 spec), props Jamie P
* Bugfix: Ensure to always filter the return value (even if false) from get_credentials(), props Jamie P
* Bugfix: Fix the Moves service so that it can get past the auth flow again (new restriction on Redirect URIs)
* Enhancement: Update the Facebook config instructions to match their UI changes
* Bugfix: Remove unnecessary %s from Google instructions

= 1.5.1 =
* Remove example OAuth application included within that library. Unnecessary and contains an XSS vulnerability.

= 1.5 =
* Enhancement: Added Moves as a service
* Bugfix: OAuth2 services were having querystring parameters stripped during POST requests. No longer doing that.
* Bugfix: typo in profile request for RunKeeper service

= 1.4 =
* WARNING: BREAKING CHANGES
* BREAKING: Depending on where you were loading Keyring, the new filtering on 'keyring_admin_url' might require some changes on your end
* BREAKING: Credentials for Services are handled slightly differently now (especially if you were using constants), so confirm they are loading before rolling out this update
* Introduce concept of "is_configured()" to Services so that you can test if a service has been set up correctly before attempting to use it
* Change get_credentials() so that it checks for a service-specific _get_credentials(), then generic constants, then in the DB
* get_credentials() is now always called when initiating a service, to load its details from the most appropriate place available
* In the default Admin UI, split services out to show which ones are configured/ready to connect and which ones need attention
* Add extensive helper instructions to the configuration pages for apps with links to where you need to go to register etc
* Update Twitter requests to 1.1 endpoint, ready for them retiring v1
* Keep track of request response codes (Props justinshreve)
* Start adding some additional information to Keyring::error() for better handling

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
