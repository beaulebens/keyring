<?php

/**
 * Jetpack/WordPress.com REST API service definition for Keyring. Clean OAuth2.
 * https://developer.wordpress.com/apps/
 */

class Keyring_Service_Jetpack extends Keyring_Service_OAuth2 {
	const NAME  = 'jetpack';
	const LABEL = 'Jetpack';
	const SCOPE = 'global';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_jetpack_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_jetpack_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://public-api.wordpress.com/oauth2/authorize', 'GET'  );
		$this->set_endpoint( 'access_token', 'https://public-api.wordpress.com/oauth2/token',     'POST' );
		$this->set_endpoint( 'self',         'https://public-api.wordpress.com/rest/v1/me/',      'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->authorization_header = 'Bearer';

		// WP.com requires exact-match redirect_uris, which means you can't include a nonce.
		// Keyring expects nonces, so this dynamically nonces during verification.
		add_action( 'pre_keyring_jetpack_verify', array( $this, 'redirect_incoming_verify' ) );

		// Need to reset the callback because Google is very strict about where it sends people
		if ( !empty( $creds['redirect_uri'] ) ) {
			$this->callback_url = $creds['redirect_uri']; // Allow user to manually enter a redirect URI
		} else {
			$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url ); // At least strip nonces, since you can't save them in your app config
		}

		add_filter( 'keyring_jetpack_request_token_params', array( $this, 'scope' ) );
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an app on WordPress.com</a>. The most important thing is to include a valid <strong>Redirect URL</strong>, which should be set to <code>%2$s</code>. You can set most other values to whatever you like.', 'keyring' ), 'https://developer.wordpress.com/apps/new/', Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>Client ID</strong> value into the <strong>API Key</strong> field, and the <strong>Client Secret</strong> value into the <strong>API Secret</strong> field and click save. You do not need an App ID.", 'keyring' ) . '</p>';
	}

	// Get access to all blogs
	function scope( $permissions = '' ) {
		$permissions['scope'] = self::SCOPE;
		return $permissions;
	}

	function redirect_incoming_verify( $request ) {
		if ( ! isset( $request['kr_nonce'] ) ) {
			// First request, from WP.com. Nonce it and move on.
			$kr_nonce = wp_create_nonce( 'keyring-verify' );
			$nonce = wp_create_nonce( 'keyring-verify-' . $this->get_name() );
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
		$token = new Keyring_Access_Token( $this->get_name(), $token['access_token'], array() );
		$this->set_token( $token );
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( Keyring_Util::is_error( $res ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'  => $res->ID,
				'name'     => $res->display_name,
				'username' => $res->username,
				'picture'  => $res->avatar_URL,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $res, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' ) . ' (@' . $token->get_meta( 'username' ) . ')';
	}

	function test_connection() {
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Jetpack', 'init' ) );
