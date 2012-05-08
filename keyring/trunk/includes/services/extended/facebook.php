<?php

/**
 * Facebook service definition for Keyring. Clean implementation of OAuth2
 */

class Keyring_Service_Facebook extends Keyring_Service_OAuth2 {
	const NAME  = 'facebook';
	const LABEL = 'Facebook';

	function __construct() {
		parent::__construct();
		
		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_facebook_manage_ui', array( &$this, 'basic_ui' ) );
		
		$this->set_endpoint( 'access_token', 'https://graph.facebook.com/oauth/access_token', 'GET' );
		$this->set_endpoint( 'self',         'https://graph.facebook.com/me',                 'GET' );
		
		if ( $creds = $this->get_credentials() ) {
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		} else if ( defined( 'KEYRING__FACEBOOK_ID' ) && defined( 'KEYRING__FACEBOOK_SECRET' ) ) {
			$this->key    = KEYRING__FACEBOOK_ID;
			$this->secret = KEYRING__FACEBOOK_SECRET;
		}
		
		$kr_nonce = wp_create_nonce( 'keyring-verify' );
		$nonce = wp_create_nonce( 'keyring-verify-facebook' );
		$this->redirect_uri = Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify', 'kr_nonce' => $kr_nonce, 'nonce' => $nonce, ) );
		
		$this->requires_token( true );
	}
	
	function request_token() {
		// Redirect to FB to handle logging in and authorizing
		$params = array(
			'client_id' => $this->key,
			'redirect_uri' => $this->redirect_uri,
			'scope' => implode( ',', apply_filters( 'keyring_facebook_scope', array( 'publish_stream' ) ) ),
		);
		wp_redirect( 'https://www.facebook.com/dialog/oauth?' . http_build_query( $params ) );
		exit;
	}
	
	/**
	 * Facebook decided to make things interesting and mix OAuth1 and 2. They return
	 * their access tokens using query string encoding, so we handle that here.
	 */
	function parse_access_token( $token ) {
		parse_str( $token, $token );
		return $token;
	}
	
	function get_display( Keyring_Token $token ) {
		return $token->get_meta( 'name' );
	}
	
	function build_token_meta( $token ) {
		$token = new Keyring_Token( 'facebook', $token['access_token'], array() );
		$this->set_token( $token );
		$me = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( !Keyring_Util::is_error( $me ) ) {
			$me = json_decode( $me );
			
			return array(
				'username' => $me->username,
				'user_id'  => $me->id,
				'name'     => $me->name,
			);
		}
		return array();
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Facebook', 'init' ) );
