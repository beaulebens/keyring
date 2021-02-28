<?php

class Keyring_Service_Pocket extends Keyring_Service_OAuth2 {
	const NAME  = 'pocket';
	const LABEL = 'Pocket';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_pocket_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_pocket_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'request_token', 'https://getpocket.com/v3/oauth/request', 'POST' );
		$this->set_endpoint( 'authorize', 'https://getpocket.com/auth/authorize', 'GET' );
		$this->set_endpoint( 'access_token', 'https://getpocket.com/v3/oauth/authorize', 'POST' );

		$creds              = $this->get_credentials();
		$this->key          = is_array( $creds ) ? $creds['key'] : '';
		$kr_nonce           = wp_create_nonce( 'keyring-verify' );
		$nonce              = wp_create_nonce( 'keyring-verify-pocket' );
		$this->redirect_uri = Keyring_Util::admin_url(
			self::NAME,
			array(
				'action'   => 'verify',
				'kr_nonce' => $kr_nonce,
				'nonce'    => $nonce,
			)
		);

		add_filter( 'keyring_request_token', array( $this, 'obtain_request_token' ), 10, 1 );
		add_filter( 'keyring_pocket_request_token_params', array( $this, 'request_token_params' ), 10, 1 );
		add_filter( 'keyring_pocket_verify_token_params', array( $this, 'verify_token_params' ), 10, 1 );
	}

	function basic_ui_intro() {
		echo '<p>' . __( "If you haven't already, you'll need to set up an app on Pocket:", 'keyring' ) . '</p>';
		echo '<ol>';
		/* translators: url */
		echo '<li>' . sprintf( __( "Head over to <a href='%s'>this page</a>", 'keyring' ), 'https://getpocket.com/developer/apps/new' ) . '</li>';
		echo '<li>' . __( 'Enter a name for your app (maybe the name of your website?) and a brief description.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Select <strong>Retrieve</strong> for Permissions, and <strong>Web</strong> for Platforms.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Accept Terms of Service and click <strong>CREATE APPLICATION</strong>', 'keyring' ) . '</li>';
		echo '</ol>';
		echo '<p>' . __( "Once you're done configuring your app, copy and paste your <strong>Consumer Key</strong> into API Key field. Leave the rest of the fields blank.", 'keyring' ) . '</p>';
	}

	function is_configured() {
		$credentials = $this->get_credentials();
		return ! empty( $credentials['key'] );
	}

	function obtain_request_token( $token ) {
		if ( 'pocket' === $token->name ) {
			$this->requires_token = false;
			$params               = array(
				'method' => $this->request_token_method,
				'body'   => array(
					'consumer_key' => $this->key,
					'redirect_uri' => $this->callback_url,
				),
			);

			$resp = $this->request( $this->request_token_url, $params );
			if ( $resp->code ) {
				$token->token = $resp->code;
			}
		}
		return $token;
	}

	function request_token_params( $params ) {
		$token = $this->store->get_token(
			array(
				'id'   => $params['state'],
				'type' => 'request',
			)
		);

		if ( isset( $token->token ) && ! empty( $token->token ) ) {
			$params = array(
				'redirect_uri'  => add_query_arg(
					array(
						'state' => $params['state'],
						'code'  => $token->token,
					),
					$params['redirect_uri']
				),
				'request_token' => $token->token,
			);
		}

		return $params;
	}

	function verify_token_params( $params ) {
		return array(
			'consumer_key' => $params['client_id'],
			'code'         => $params['code'],
		);
	}

	function verify_token_post_params( $params ) {
		return array(
			'headers' => array(
				'Content-Type' => 'application/json; charset=UTF-8',
				'X-Accept'     => 'application/json',
			),
			'body'    => $params['body'],
		);
	}

	// Pocket always returns urlencoded access tokens for some reason
	function parse_access_token( $token ) {
		parse_str( $token, $vars );
		return $vars;
	}

	function request( $url, array $params = array() ) {
		$params['body']['consumer_key'] = $this->key;

		$params['headers']['Content-Type'] = 'application/json; charset=UTF-8';
		$params['headers']['X-Accept']     = 'application/json';

		$token = $this->get_token();
		if ( $token ) {
			$params['body']['access_token'] = $token->token;
		}

		$params['body'] = json_encode( $params['body'] );

		return parent::request( $url, $params );
	}

	function build_token_meta( $token ) {
		if ( ! isset( $token['username'] ) || empty( $token['username'] ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id' => $token['username'],
				'name'    => $token['username'],
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, null, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
		$response = $this->request(
			'https://getpocket.com/v3/get',
			array(
				'method' => 'POST',
				'body'   => array(
					'count' => 1,
				),
			)
		);
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Pocket', 'init' ) );
