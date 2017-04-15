<?php

/**
 * Pinterest service definition for Keyring.
 * https://developers.pinterest.com/
 */

class Keyring_Service_Pinterest extends Keyring_Service_OAuth2 {
	const NAME  = 'pinterest';
	const LABEL = 'Pinterest';
	const SCOPE = 'read_public';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_pinterest_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_pinterest_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://api.pinterest.com/oauth/',                                            'GET'  );
		$this->set_endpoint( 'access_token', 'https://api.pinterest.com/v1/oauth/token',                                    'POST' );
		$this->set_endpoint( 'self',         'https://api.pinterest.com/v1/me/?fields=first_name,last_name,username,image', 'GET'  ); // undocumented, but required to get the `image` in a single request

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		// Send auth token in query string
		$this->authorization_header    = false;
		$this->authorization_parameter = 'access_token';

		add_filter( 'keyring_pinterest_request_token_params', array( $this, 'request_token_params' ) );

		// Handle Pinterest's annoying limitation of not allowing us to redirect to a dynamic URL
		add_action( 'pre_keyring_pinterest_verify', array( $this, 'redirect_incoming_verify' ) );

		// Strip nonces, since you can't save them in your app config, and Pinterest is strict about redirect_uris
		// Can also only return you to an HTTPS address
		$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url );
	}

	function request_token_params( $params ) {
		$params['scope'] = apply_filters( 'keyring_' . $this->get_name() . '_scope', self::SCOPE );
		return $params;
	}

	function redirect_incoming_verify( $request ) {
		if ( !isset( $request['kr_nonce'] ) ) {
			// First request, from Pinterest. Nonce it and move on.
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

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an API client on Pinterest</a>. The most important setting is the <strong>OAuth redirect_uri</strong>, which should be set to <code>%2$s</code>. You can set the other values to whatever you like.', 'keyring' ), 'https://developers.pinterest.com/apps/', Keyring_Util::admin_url( 'pinterest', array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you're approved, copy your <strong>CLIENT ID</strong> value into the <strong>API Key</strong> field, and the <strong>CLIENT SECRET</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Pinterest).", 'keyring' ) . '</p>';
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
				'user_id'  => $response->data->id,
				'username' => $response->data->username,
				'name'     => $response->data->first_name . ' ' . $response->data->last_name,
				'picture'  => $response->data->image->{'60x60'}->url // Pinterest violate their own docs that this should be 'small'
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

add_action( 'keyring_load_services', array( 'Keyring_Service_Pinterest', 'init' ) );
