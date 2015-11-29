<?php

/**
 * 500px service definition for Keyring. Implementation of OAuth1a
 */

class Keyring_Service_500px extends Keyring_Service_OAuth1 {
	const NAME  = '500px';
	const LABEL = '500px';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_500px_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_500px_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->authorization_header = true;
		$this->authorization_realm = 'api.500px.com';

		$this->set_endpoint( 'request_token', 'https://api.500px.com/v1/oauth/request_token', 'GET' );
		$this->set_endpoint( 'authorize',     'https://api.500px.com/v1/oauth/authorize',     'GET' );
		$this->set_endpoint( 'access_token',  'https://api.500px.com/v1/oauth/access_token',  'GET' );
		$this->set_endpoint( 'authenticate',  'https://api.500px.com/v1/oauth/authorize',     'GET' );
		$this->set_endpoint( 'users',  'https://api.500px.com/v1/users',                      'GET' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'To connect to 500px, you\'ll need to <a href="%s">create an application at 500px.com</a>.', 'keyring' ), 'https://500px.com/settings/applications' ) . '</p>';
		echo '<p>' . __( "Once you've created your app, enter the <strong>Consumer Key</strong> and <strong>Consumer Secret</strong> below.", 'keyring' ) . '</p>';
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( "https://api.500px.com/v1/users", array( 'method' => 'GET' ) );

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'  => $response->user->id,
				'username' => $response->user->username,
				'name'     => $response->user->fullname,
				'picture'  => $response->user->userpic_https_url,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, '500px', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'username' );
	}

	function test_connection() {
		$response = $this->request( $this->users_url, array( 'method' => $this->users_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_500px', 'init' ) );
