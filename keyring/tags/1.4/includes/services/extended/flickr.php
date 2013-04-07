<?php

/**
 * Flickr service definition for Keyring. Implementation of OAuth1a
 */

class Keyring_Service_Flickr extends Keyring_Service_OAuth1 {
	const NAME  = 'flickr';
	const LABEL = 'Flickr';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_flickr_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_flickr_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'request_token', 'http://www.flickr.com/services/oauth/request_token', 'GET' );
		$this->set_endpoint( 'authorize',     'http://www.flickr.com/services/oauth/authorize',     'GET' );
		$this->set_endpoint( 'access_token',  'http://www.flickr.com/services/oauth/access_token',  'GET' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	function basic_ui_intro() {
		echo '<p>' . __( "To connect to Flickr, you'll need to <a href='http://www.flickr.com/services/apps/create/apply/?'>create an application at Flickr.com</a>. If this is a personal website then you can use a non-commercial key (which will be approved automatically).", 'keyring' ) . '</p>';
		echo '<p>' . __( "Once you've created your app, enter the API <strong>Key</strong> and <strong>Secret</strong> below (App ID is not required for Flickr apps).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		// Need to make a request to get full information
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);
		$url = "http://api.flickr.com/services/rest/?";
		$params = array(
			'method'  => 'flickr.people.getInfo',
			'api_key' => $this->key,
			'user_id' => $token['user_nsid'],
		);
		$url = $url . http_build_query( $params );

		$response = $this->request( $url, array( 'method' => 'GET' ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'  => $token['user_nsid'],
				'username' => $token['username'],
				'name'     => $token['fullname'],
				'picture'  => "http://farm{$response->person->iconfarm}.staticflickr.com/{$response->person->iconserver}/buddyicons/{$token['user_nsid']}.jpg",
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'flickr', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		$return = '';
		$meta = $token->get_meta();
		if ( !empty( $meta['name'] ) )
			return $meta['name'];
		else if ( !empty( $meta['username'] ) )
			return $meta['username'];
	}

	/**
	 * Custom request method so that we can force JSON for Flickr, which otherwise
	 * uses XML.
	 * @param  string $url    The URL to request
	 * @param  array  $params Any additional parameters requried for this reqeust
	 * @return Mixed with either a Keyring_Error, or a decoded JSON response object
	 */
	function request( $url, array $params = array() ) {
		// http://www.flickr.com/services/api/response.json.html
		$url = add_query_arg(
			array(
				'format'         => 'json', // Always return JSON
				'nojsoncallback' => 1, // Don't wrap it in a callback
			),
			$url );
		return parent::request( $url, $params );
	}

	/**
	 * Since we're forcing all requests to be for JSON data, we can decode
	 * all responses as JSON as well.
	 * @param  string $response Full content of the response
	 * @return JSON object representation of the response
	 */
	function parse_response( $response ) {
		return json_decode( $response );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Flickr', 'init' ) );
