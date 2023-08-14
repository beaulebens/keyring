<?php

/**
 * Nextdoor service definition.
 */

class Keyring_Service_Nextdoor extends Keyring_Service_OAuth2 {
	const NAME  = 'nextdoor';
	const LABEL = 'Nextdoor';


	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_nextdoor_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_nextdoor_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint("access_token", "https://auth.nextdoor.com/v2/token", "POST" );
        $this->set_endpoint("authorize", "https://nextdoor.com/v3/authorize/?scope=openid%20post:write&", "POST");

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}
		$admin_url          = Keyring_Util::admin_url();
		$this->redirect_uri = substr( $admin_url, 0, strpos( $admin_url, '?' ) );

		// Send authorization via header
		$this->authorization_header = 'Bearer';
		add_filter( 'keyring_nextdoor_request_token_params', array( $this, 'request_token_params' ) );
		add_filter( 'keyring_nextdoor_verify_token_params', array( $this, 'verify_token_params' ) );
		add_filter( 'keyring_nextdoor_verify_token_post_params', array( $this, 'verify_token_post_params' ) );
		add_filter( 'keyring_access_token', array( $this, 'fix_access_token_meta' ), 10, 2 );
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'To use the Nextdoor service you need to be manually approved. Please reach out to get your client id and client secret.', 'keyring' )) . '</p>';
	}

	function request_token_params( $params ) {
		$url_components = parse_url( $params['redirect_uri'] );
		parse_str( $url_components['query'], $redirect_state );
		$redirect_state['state'] = $params['state'];
		$params['state']         = Keyring_Util::get_hashed_parameters( $redirect_state );
		$params['redirect_uri']  = $this->redirect_uri;

		return $params;
	}

	function verify_token_params( $params ) {
		unset( $params['client_id'] );
		unset( $params['client_secret'] );
		$params['redirect_uri']  = $this->redirect_uri;
		// $params[''] = ($params['code'] . '=');
		return $params;
	}

	function verify_token_post_params( $params ) {
		$params['headers'] = $this->get_basic_auth();

		return $params;
	}

	function fix_access_token_meta( $access_token, $token ) {
		error_log('testing fix access token meta');
		if ( 'nextdoor' !== $access_token->get_name() ) {
			return $access_token;
		}

		return new Keyring_Access_Token(
			$this->get_name(),
			$token['access_token'],
			array_merge( $access_token->get_meta(), $this->get_token()->get_meta() ) // refresh_token has been updated, and we want to make sure we store it
		);
	}

	function get_basic_auth() {
		return array( 'Authorization' => 'Basic ' . base64_encode( $this->key . ':' . $this->secret ) );
	}

	function build_token_meta( $token ) {
		$decoded_id_token = json_decode(base64_decode(explode('.', $token['id_token'])[1]));
		error_log('testing build_token_meta id token' . print_r($decoded_id_token->sub, true));
		$meta = array(
			'account_id'      => $decoded_id_token->sub,
			'expires'       => time() + $token['expires_in'],
		);

		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				$meta
			)
		);
		error_log('testing build_token_meta meta' . print_r($meta, true));


		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function refresh_token() {
		Keyring_Util::debug( 'Nextdoor::refresh_token()' );
		// Request a new token, using the refresh_token
		$token = $this->get_token();
		$meta  = $token->get_meta();
		if ( empty( $meta['refresh_token'] ) ) {
			return false;
		}

		// Don't bother if this token is valid for a while
		if ( ! $token->is_expired( 20 ) ) {
			return;
		}

		// Refresh our access token
		$response = wp_remote_post(
			$this->refresh_url,
			array(
				'method'  => $this->refresh_method,
				'headers' => $this->get_basic_auth(),
				'body'    => array(
					'grant_type'    => 'refresh_token',
					'refresh_token' => $meta['refresh_token'],
				),
			)
		);
		Keyring_Util::debug( $response );

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$return                = json_decode( wp_remote_retrieve_body( $response ) );
		$meta['refresh_token'] = $return->refresh_token;
		$meta['expires']       = time() + $return->expires_in;
		$access_token          = new Keyring_Access_Token(
			$this->get_name(),
			$return->access_token,
			$meta,
			$token->get_uniq_id()
		);

		// Update store, and switch to new token
		$this->store->update( $access_token );
		$this->set_token( $access_token );
	}

	// Need to potentially refresh token before each request
	function request( $url, array $params = array() ) {
		$this->refresh_token();
		return parent::request( $url, $params );
	}

	function test_connection() {
		Keyring_Util::debug( 'Nextdoor::test_connection()' );
		$response = $this->request( $this->profile_url, array( 'method' => $this->profile_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Nextdoor', 'init' ) );