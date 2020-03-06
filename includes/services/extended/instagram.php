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
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_instagram_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_instagram_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://api.instagram.com/oauth/authorize/', 'GET' );
		$this->set_endpoint( 'access_token', 'https://api.instagram.com/oauth/access_token', 'POST' );
		$this->set_endpoint( 'self', 'https://graph.instagram.com/me', 'GET' );

		$creds        = $this->get_credentials();
		$this->app_id = $creds['app_id'];
		$this->key    = $creds['key'];
		$this->secret = $creds['secret'];

		// The new Instagram API is very fussy about the redirect uri, so this strips the query params 
		// from the default admin url
		$admin_url = Keyring_Util::admin_url();
		$this->redirect_uri = substr($admin_url,0,strpos($admin_url, '?'));

		$this->authorization_header    = false; // Send in querystring
		$this->authorization_parameter = 'access_token';
		add_filter( 'keyring_instagram_request_token_params', array( $this, 'filter_request_token' ) );
		add_filter( 'keyring_instagram_verify_token_post_params', array( $this, 'verify_token_post_params' ) );
	}

	function verify_token_post_params( $params ) {
		$params['body']['redirect_uri'] = $this->redirect_uri;
		return $params;
	}

	/**
	 * Add scope to the outbound URL, and allow developers to modify it, and also 
	 * pack all of the redirct_uri params into the state param as Instagram does strips
	 * these before redirecting
	 * @param  array $params Core request parameters
	 * @return Array containing originals, plus the scope parameter, and a serialized state param
	 */
	function filter_request_token( $params ) {
		$params['scope'] = apply_filters( 'keyring_' . $this->get_name() . '_scope', 'user_profile,user_media' );

		// The Instagram API does not return redirect_uri params, so we need to pack these 
		// into the state param
		$url_components = parse_url( $params['redirect_uri'] );
		parse_str($url_components['query'], $redirect_state);
		$redirect_state['state'] = $params['state'];
		$params['redirect_uri'] = $this->redirect_uri;
		$params['state'] = base64_encode(serialize( $redirect_state ));
		
		return $params;
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an OAuth client on Instagram</a>. The most important setting is the <strong>OAuth redirect_uri</strong>, which should be set to <code>%2$s</code>. You can set the other values to whatever you like.', 'keyring' ), 'http://instagram.com/developer/clients/register/', Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>CLIENT ID</strong> value into the <strong>API Key</strong> field, and the <strong>CLIENT SECRET</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Instagram).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		if ( empty( $token['user'] ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'  => $token['user']->id,
				'username' => $token['user']->username,
				'name'     => $token['user']->full_name,
				'picture'  => $token['user']->profile_picture,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, null, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Instagram', 'init' ) );
