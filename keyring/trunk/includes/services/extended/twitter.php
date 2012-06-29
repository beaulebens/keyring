<?php

/**
 * Twitter service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Twitter extends Keyring_Service_OAuth1 {
	const NAME  = 'twitter';
	const LABEL = 'Twitter';
	
	var $authorization_header;
	var $authorization_realm;

	function __construct() {
		parent::__construct();
		
		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_twitter_manage_ui', array( $this, 'basic_ui' ) );
		
		$this->authorization_header = true;
		$this->authorization_realm = "twitter.com";
		
		$this->set_endpoint( 'request_token', 'https://twitter.com/oauth/request_token', 'POST' );
		$this->set_endpoint( 'authorize',     'https://twitter.com/oauth/authorize',     'GET' );
		$this->set_endpoint( 'access_token',  'https://twitter.com/oauth/access_token',  'POST' );
		
		if ( $creds = $this->get_credentials() ) {
			$this->key = $creds['key'];
			$this->secret = $creds['secret'];
		} else if ( defined( 'KEYRING__TWITTER_KEY' ) && defined( 'KEYRING__TWITTER_SECRET' ) ) {
			$this->key = KEYRING__TWITTER_KEY;
			$this->secret = KEYRING__TWITTER_SECRET;
		}
		
		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
		
		$this->requires_token( true );
	}
	
	function parse_response( $response ) {
		return json_decode( $response );
	}
	
	function build_token_meta( $token ) {
		return array(
			'user_id' => $token['user_id'],
			'username' => $token['screen_name'],
		);
	}

	function get_display( Keyring_Token $token ) {
		return '@' . $token->get_meta( 'username' );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Twitter', 'init' ) );
