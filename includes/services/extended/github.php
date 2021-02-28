<?php

/**
 * Github service definition for Keyring.
 * https://developer.github.com/apps/building-oauth-apps/
 */

class Keyring_Service_Github extends Keyring_Service_OAuth2 {
	const NAME  = 'github';
	const LABEL = 'GitHub';
	const SCOPE = '';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_github_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_github_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://github.com/login/oauth/authorize', 'GET' );
		$this->set_endpoint( 'access_token', 'https://github.com/login/oauth/access_token', 'POST' );
		$this->set_endpoint( 'self', 'https://api.github.com/user', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer         = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'token';
		$this->authorization_parameter = false;

		add_filter( 'keyring_github_request_token_params', array( $this, 'request_token_params' ) );
		add_filter( 'keyring_github_verify_token_post_params', array( $this, 'verify_token_post_params' ) );

		add_action( 'pre_keyring_github_verify', array( $this, 'redirect_incoming_verify' ) );

		// Strip nonces, since you can't save them in your app config, and GitHub is strict about redirect_uris
		// Can also only return you to an HTTPS address
		$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url );
	}

	function verify_token_post_params( $params ) {
		$params['headers'] = array(
			'Accept' => 'application/json',
		);
		return $params;
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an OAuth client on GitHub</a>. The most important setting is the <strong>OAuth redirect_uri</strong>, which should be set to <code>%2$s</code>. You can set the other values to whatever you like.', 'keyring' ), 'https://developer.github.com/apps/building-oauth-apps/creating-an-oauth-app/', Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>CLIENT ID</strong> value into the <strong>API Key</strong> field, and the <strong>CLIENT SECRET</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for GitHub).", 'keyring' ) . '</p>';
	}

	function request_token_params( $params ) {
		$params['scope'] = apply_filters( 'keyring_' . $this->get_name() . '_scope', self::SCOPE );
		return $params;
	}

	function redirect_incoming_verify( $request ) {
		if ( ! isset( $request['kr_nonce'] ) ) {
			// First request, from GitHub. Nonce it and move on.
			$kr_nonce = wp_create_nonce( 'keyring-verify' );
			$nonce    = wp_create_nonce( 'keyring-verify-' . $this->get_name() );
			wp_safe_redirect(
				Keyring_Util::admin_url(
					$this->get_name(),
					array(
						'action'   => 'verify',
						'kr_nonce' => $kr_nonce,
						'nonce'    => $nonce,
						'state'    => $request['state'],
						'code'     => $request['code'], // Auth code from successful response (maybe)
					)
				)
			);
			exit;
		}
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
				'user_id'  => $response->id,
				'username' => $response->login,
				'name'     => $response->name,
				'picture'  => $response->avatar_url,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $response, $this );
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

add_action( 'keyring_load_services', array( 'Keyring_Service_Github', 'init' ) );
