<?php

/**
 * Instagram service definition for Keyring.
 * http://instagram.com/developer/
 */

class Keyring_Service_Instagram extends Keyring_Service_OAuth2 {
	const NAME  = 'instagram';
	const LABEL = 'Instagram';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_instagram_manage_ui', array( $this, 'basic_ui' ) );

		$this->set_endpoint( 'authorize',    'https://api.instagram.com/oauth/authorize/', 'GET' );
		$this->set_endpoint( 'access_token', 'https://api.instagram.com/oauth/access_token', 'POST' );
		$this->set_endpoint( 'self',         'https://api.Instagram.com/v2/users/self',   'GET' );

		if ( defined( 'KEYRING__INSTAGRAM_KEY' ) && defined( 'KEYRING__INSTAGRAM_SECRET' ) ) {
			$this->key    = KEYRING__INSTAGRAM_KEY;
			$this->secret = KEYRING__INSTAGRAM_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = false; // Send in querystring
		$this->authorization_parameter = 'access_token';
	}

	function build_token_meta( $token ) {
		if ( empty( $token['user'] ) )
			return array();

		return array(
			'user_id'  => $token['user']->id,
			'username' => $token['user']->username,
			'name'     => $token['user']->full_name,
			'picture'  => $token['user']->profile_picture,
		);
	}

	function get_display( Keyring_Token $token ) {
		return $token->get_meta( 'name' );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Instagram', 'init' ) );
