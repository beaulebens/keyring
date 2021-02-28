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
		add_action( 'keyring_flickr_manage_ui', array( $this, 'basic_ui' ) );

		$this->set_endpoint( 'request_token', 'http://www.flickr.com/services/oauth/request_token', 'GET' );
		$this->set_endpoint( 'authorize',     'http://www.flickr.com/services/oauth/authorize',     'GET' );
		$this->set_endpoint( 'access_token',  'http://www.flickr.com/services/oauth/access_token',  'GET' );

		if ( defined( 'KEYRING__FLICKR_KEY' ) && defined( 'KEYRING__FLICKR_SECRET' ) ) {
			$this->key = KEYRING__FLICKR_KEY;
			$this->secret = KEYRING__FLICKR_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->key = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	function build_token_meta( $token ) {
		return array(
			'user_id'  => $token['user_nsid'],
			'username' => $token['username'],
			'name'     => $token['fullname'],
		);
	}

	function get_display( Keyring_Token $token ) {
		$return = '';
		$meta = $token->get_meta();
		if ( !empty( $meta['full_name'] ) )
			$return = $meta['full_name'];
		if ( !empty( $return ) )
			$return .= ' (' . $meta['username'] . ')';
		else
			$return = $meta['username'];
		return $return;
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
				'format' => 'json', // Always return JSON
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
