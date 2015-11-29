<?php

/**
 * Fitbit service definition for Keyring.
 * https://dev.fitbit.com/
 */

class Keyring_Service_Fitbit extends Keyring_Service_OAuth2 {
	const NAME  = 'fitbit';
	const LABEL = 'Fitbit';
	const SCOPE = 'profile activity heartrate location nutrition sleep weight'; // Everything interesting; https://dev.fitbit.com/docs/oauth2/#scope

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_fitbit_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_fitbit_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://www.fitbit.com/oauth2/authorize',      'GET'  );
		$this->set_endpoint( 'access_token', 'https://api.fitbit.com/oauth2/token',          'POST' );
		$this->set_endpoint( 'refresh',      'https://api.fitbit.com/oauth2/token',          'POST' );
		$this->set_endpoint( 'profile',      'https://api.fitbit.com/1/user/-/profile.json', 'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		// Fitbit requires an exact match on Redirect URI, which means we can't send any nonces
		$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url );
		add_action( 'pre_keyring_fitbit_verify', array( $this, 'redirect_incoming_verify' ) );

		// Send authorization via header
		$this->authorization_header = 'Bearer';

		add_filter( 'keyring_fitbit_request_token_params', array( $this, 'request_token_params' ) );
		add_filter( 'keyring_fitbit_verify_token_params', array( $this, 'verify_token_params' ) );
		add_filter( 'keyring_fitbit_verify_token_post_params', array( $this, 'verify_token_post_params' ) );

		add_filter( 'keyring_access_token', array( $this, 'fix_access_token_meta' ), 10, 2 );
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'Go to Fitbit and <a href="%s">create a new application</a>, which allows Keyring to talk to Fitbit.', 'keyring' ), 'https://dev.fitbit.com/apps/new' ) . '</p>';
		echo '<p>' . sprintf( __( "You can use anything for the name/description details etc. Make sure you set the <strong>OAuth 2.0 Application Type</strong> to <strong>Personal</strong> (grants you some extra access) and set your <strong>Callback URL</strong> to <code>%s</code>. You only need Read-Only access if you are syncing data, but Read &amp; Write will let you update details as well.", 'keyring' ), Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify' ) ) ) . '</p>';
	}

	function request_token_params( $params ) {
		$params['scope'] = apply_filters( 'keyring_fitbit_scope', self::SCOPE );
		return $params;
	}

	function verify_token_params( $params ) {
		unset( $params['client_id'] );
		unset( $params['client_secret'] );
		return $params;
	}

	function verify_token_post_params( $params ) {
		$params['headers'] = $this->get_basic_auth();
		return $params;
	}

	function fix_access_token_meta( $access_token, $token ) {
		if ( 'fitbit' !== $access_token->get_name() ) {
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

	function redirect_incoming_verify( $request ) {
		if ( ! isset( $request['kr_nonce'] ) ) {
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
		$meta = array(
			'user_id'       => $token['user_id'],
			'expires'       => time() + $token['expires_in'],
			'refresh_token' => $token['refresh_token'],
		);

		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				$meta
			)
		);

		$response = $this->request( $this->profile_url );
		if ( ! Keyring_Util::is_error( $response ) ) {
			$meta['name']       = $response->user->fullName;
			$meta['picture']    = $response->user->avatar;
			$meta['first_date'] = $response->user->memberSince;
			$meta['_classname'] = get_called_class();
		}

		return apply_filters( 'keyring_access_token_meta', $meta, self::NAME, $token, array(), $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function refresh_token() {
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
		$response = wp_remote_post( $this->refresh_url, array(
			'method'  => $this->refresh_method,
			'headers' => $this->get_basic_auth(),
			'body'    => array(
				'grant_type'    => 'refresh_token',
				'refresh_token' => $meta['refresh_token'],
			)
		) );

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$return = json_decode( wp_remote_retrieve_body( $response ) );
		$meta['refresh_token'] = $return->refresh_token;
		$meta['expires']       = $return->expires_in;
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$return->access_token,
				$meta
			)
		);
	}

	// Need to potentially refresh token before each request
	function request( $url, array $params = array() ) {
		$this->refresh_token();
		return parent::request( $url, $params );
	}

	function test_connection() {
		$response = $this->request( $this->profile_url, array( 'method' => $this->profile_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Fitbit', 'init' ) );
