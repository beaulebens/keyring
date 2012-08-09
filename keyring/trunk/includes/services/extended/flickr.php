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
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Flickr', 'init' ) );
