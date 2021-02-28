<?php

/**
 * Instagram service definition for Keyring.
 * http://instagram.com/developer/
 */

class Keyring_Service_Instagram_Basic_Display extends Keyring_Service_OAuth2 {
	const NAME  = 'instagram-basic-display';
	const LABEL = 'Instagram Basic';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_' . $this->get_name() . '_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_' . $this->get_name() . '_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://api.instagram.com/oauth/authorize/', 'GET' );
		$this->set_endpoint( 'access_token', 'https://api.instagram.com/oauth/access_token', 'POST' );
		$this->set_endpoint( 'exchange_token', 'https://graph.instagram.com/access_token', 'GET' );
		$this->set_endpoint( 'refresh_token', 'https://graph.instagram.com/refresh_access_token', 'GET' );
		$this->set_endpoint( 'self', 'https://graph.instagram.com/me', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		// The new Instagram API is very fussy about the redirect uri, so this strips the query params
		// from the default admin url
		$admin_url          = Keyring_Util::admin_url();
		$this->redirect_uri = substr( $admin_url, 0, strpos( $admin_url, '?' ) );

		$this->authorization_header    = false; // Send in querystring
		$this->authorization_parameter = 'access_token';
		add_filter( 'keyring_' . $this->get_name() . '_request_token_params', array( $this, 'filter_request_token' ) );
		add_filter( 'keyring_' . $this->get_name() . '_verify_token_post_params', array( $this, 'verify_token_post_params' ) );
	}

	function verify_token_post_params( $params ) {
		$params['body']['redirect_uri'] = $this->redirect_uri;
		return $params;
	}

	/**
	 * Add scope to the outbound URL, and allow developers to modify it, and also
	 * pack all of the redirct_uri params into the state param as Instagram strips
	 * these before redirecting
	 * @param  array $params Core request parameters
	 * @return Array containing originals, plus the scope parameter, and a serialized state param
	 */
	function filter_request_token( $params ) {
		$params['scope'] = apply_filters( 'keyring_' . $this->get_name() . '_scope', 'user_profile,user_media' );

		// The Instagram API does not return redirect_uri params, so we need to pack these
		// into the state param
		$url_components = parse_url( $params['redirect_uri'] );
		parse_str( $url_components['query'], $redirect_state );
		$redirect_state['state'] = $params['state'];
		$params['state']         = Keyring_Util::get_hashed_parameters( $redirect_state );
		$params['redirect_uri']  = $this->redirect_uri;

		return $params;
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an OAuth client on Instagram</a>. The most important setting is the <strong>OAuth redirect_uri</strong>, which should be set to <code>%2$s</code>. You can set the other values to whatever you like.', 'keyring' ), 'http://instagram.com/developer/clients/register/', Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>CLIENT ID</strong> value into the <strong>API Key</strong> field, and the <strong>CLIENT SECRET</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Instagram).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( add_query_arg( 'fields', 'id, username', $this->self_url ), array( 'method' => $this->self_method ) );

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id' => $response->id,
				'name'    => $response->username,
			);
			if ( ! empty( $token['expires_in'] ) ) {
				$meta['expires'] = time() + $token['expires_in'];
			}
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

	function parse_access_token( $token ) {
		//Somewhat of a hack, but we need a place to exchange for a long lived token
		$token = (array) json_decode( $token );
		return $this->exchange_for_long_lived_token( $token );
	}

	function exchange_for_long_lived_token( $token ) {
		$params = array(
			'client_secret' => $this->secret,
			'grant_type'    => 'ig_exchange_token',
			'access_token'  => $token['access_token'],
		);
		$url    = $this->exchange_token_url . '?' . http_build_query( $params );
		$result = wp_remote_get( $url );
		Keyring_Util::debug( 'Instagram Exchange Token Response' );
		Keyring_Util::debug( $result );
		if ( 200 === wp_remote_retrieve_response_code( $result ) ) {
			$token = array_merge( $token, (array) json_decode( wp_remote_retrieve_body( $result ) ) );
			return $token;
		}

		Keyring::error( __( 'There was a problem exchanging an Instagram access token for a long lived one.', 'keyring' ), array( 'remote_user_id' => $token['user_id'] ) );
		//TODO: Decide if we should exit here or simply carry on with the short lived token.
		//It seems like Keyring::error exits at this point anyway.
		return $token;
	}

	function request( $url, array $params = array() ) {
		$this->maybe_refresh_token();
		return parent::request( $url, $params );
	}

	function maybe_refresh_token() {
		$token = $this->get_token();
		if ( empty( $token ) ) {
			return false;
		}

		//Long lived tokens last for 60 days, but
		//refresh them after 36 hours to give them the
		//best chance of not expiring.
		if ( ! $token->is_expired( 5054400 ) ) {
			return;
		}

		$params = array(
			'grant_type'   => 'ig_refresh_token',
			'access_token' => (string) $token,
		);

		$result = wp_remote_get( $this->refresh_token_url . '?' . http_build_query( $params ) );

		if ( 200 !== wp_remote_retrieve_response_code( $result ) ) {
			return false;
		}

		$response        = json_decode( wp_remote_retrieve_body( $result ) );
		$meta            = $token->get_meta();
		$meta['expires'] = time() + $response->expires_in;

		// Build access token
		$access_token = new Keyring_Access_Token(
			$this->get_name(),
			$response->access_token,
			$meta,
			$this->token->unique_id
		);

		// Store the updated access token
		$access_token = apply_filters( 'keyring_access_token', $access_token, (array) $response );
		$this->store->update( $access_token );

		// And switch to using it
		$this->set_token( $access_token );
	}


}

add_action( 'keyring_load_services', array( 'Keyring_Service_Instagram_Basic_Display', 'init' ) );
