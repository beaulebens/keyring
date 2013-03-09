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
		if ( ! KEYRING__HEADLESS_MODE )
			add_action( 'keyring_facebook_manage_ui', array( $this, 'basic_ui' ) );

		$this->set_endpoint( 'authorize',     'https://www.facebook.com/dialog/oauth',        'GET' );
		$this->set_endpoint( 'access_token', 'https://graph.facebook.com/oauth/access_token', 'GET' );
		$this->set_endpoint( 'self',         'https://graph.facebook.com/me',                 'GET' );

		if (
			defined( 'KEYRING__FACEBOOK_ID' )
		&&
			defined( 'KEYRING__FACEBOOK_SECRET' )
		) {
			$this->app_id  = KEYRING__FACEBOOK_ID;
			$this->key     = KEYRING__FACEBOOK_ID; // Intentionally duplicated from above
			$this->secret  = KEYRING__FACEBOOK_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->app_id  = $creds['key'];
			$this->key     = $creds['key']; // Intentionally duplicated from above
			$this->secret  = $creds['secret'];
		}

		$kr_nonce = wp_create_nonce( 'keyring-verify' );
		$nonce    = wp_create_nonce( 'keyring-verify-facebook' );
		$this->redirect_uri = Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify', 'kr_nonce' => $kr_nonce, 'nonce' => $nonce, ) );

		$this->requires_token( true );

		add_filter( 'keyring_facebook_request_token_params', array( $this, 'filter_request_token' ) );
	}

	/**
	 * Add scope to the outbound URL, and allow developers to modify it
	 * @param  array $params Core request parameters
	 * @return Array containing originals, plus the scope parameter
	 */
	function filter_request_token( $params ) {
		if ( $scope = implode( ',', apply_filters( 'keyring_facebook_scope', array() ) ) )
			$params['scope'] = $scope;
		return $params;
	}

	/**
	 * Facebook decided to make things interesting and mix OAuth1 and 2. They return
	 * their access tokens using query string encoding, so we handle that here.
	 */
	function parse_access_token( $token ) {
		parse_str( $token, $token );
		return $token;
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'username' => $response->username,
				'user_id'  => $response->id,
				'name'     => $response->name,
				'picture'  => "https://graph.facebook.com/{$response->id}/picture?type=large",
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'facebook', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( !Keyring_Util::is_error( $res ) )
			return true;

		return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Facebook', 'init' ) );
