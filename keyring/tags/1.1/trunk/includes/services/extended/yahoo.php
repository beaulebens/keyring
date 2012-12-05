<?php

/**
 * Yahoo service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Yahoo extends Keyring_Service_OAuth1 {
	const NAME  = 'yahoo';
	const LABEL = 'Yahoo! Updates';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_yahoo_manage_ui', array( $this, 'basic_ui' ) );

		$this->set_endpoint( 'request_token', 'https://api.login.yahoo.com/oauth/v2/get_request_token', 'POST' );
		$this->set_endpoint( 'authorize',     'https://api.login.yahoo.com/oauth/v2/request_auth',      'GET' );
		$this->set_endpoint( 'access_token',  'https://api.login.yahoo.com/oauth/v2/get_token',         'POST' );

		if ( defined( 'KEYRING__YAHOO_KEY' ) && defined( 'KEYRING__YAHOO_SECRET' ) ) {
			$this->key = KEYRING__YAHOO_KEY;
			$this->secret = KEYRING__YAHOO_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->key = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function custom_token_object( $token_object, $token ) {
		$token_object->guid = $token['xoauth_yahoo_guid'];
		$token_object->consumer = $this->key;
		$token_object->sessionHandle = $token['oauth_session_handle'];

		$now = time();

		if( !empty( $token['oauth_expires_in'] ) )
			$token_object->tokenExpires = $now + $token["oauth_expires_in"];
		else
			$token_object->tokenExpires = -1;

		if ( !empty( $token['oauth_authorization_expires_in'] ) )
			$token_object->handleExpires = $now + $token["oauth_authorization_expires_in"];
		else
			$token_object->handleExpires = -1;

		return $token_object;
	}

	function build_token_meta( $token ) {
		$expires = isset( $token['oauth_expires_in'] ) ? gmdate( 'Y-m-d H:i:s', time() + $token['oauth_expires_in'] ) : 0;
		Keyring_Util::debug( $token );

		$this->set_token(
			new Keyring_Token(
				'yahoo',
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		// Get user profile information
		$response = $this->request( "http://social.yahooapis.com/v1/user/{$token['xoauth_yahoo_guid']}/profile?format=json" );

		if ( Keyring_Util::is_error( $response ) )
			return array();

		$this->person = $response->profile;
print_r($this->person);
		$meta = array(
			'user_id'   => $token['xoauth_yahoo_guid'],
			'name' => $this->person->nickname,
		);

		return $meta;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Yahoo', 'init' ) );
