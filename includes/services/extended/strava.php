<?php

/**
 * Strava service definition for Keyring, supporting the Strava API v3
 * https://developers.strava.com/
 */

class Keyring_Service_Strava extends Keyring_Service_OAuth2 {
	const NAME  = 'strava';
	const LABEL = 'Strava';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_strava_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_strava_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://www.strava.com/oauth/authorize', 'GET' );
		$this->set_endpoint( 'access_token', 'https://www.strava.com/oauth/token', 'POST' );
		$this->set_endpoint( 'refresh', 'https://www.strava.com/oauth/token', 'POST' );
		$this->set_endpoint( 'deauthorize', 'https://www.strava.com/oauth/deauthorize', 'POST' );
		$this->set_endpoint( 'user', 'https://www.strava.com/api/v3/athlete', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;

		add_filter( 'keyring_' . $this->get_name() . '_request_token_params', array( $this, 'request_token_params' ) );
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'You\'ll need to <a href="%s">create a new application</a> on Strava so that you can connect.', 'keyring' ), 'https://www.strava.com/settings/api' ) . '</p>';
		echo '<p>' . __( "Once you've registered your application, copy the <strong>Application Name</strong> into the <strong>App ID</strong>, the <strong>Client ID</strong> and the <strong>Client Secret</strong> into the <strong>API Key</strong> and <strong>API Secret</strong> fields below,.", 'keyring' ) . '</p>';
	}

	function request_token_params( $params ) {
		$params['scope'] = apply_filters( 'keyring_' . $this->get_name() . '_scope', 'read,activity:read_all' );
		return $params;
	}

	// Need to potentially refresh token before each request
	function request( $url, array $params = array() ) {
		$this->maybe_refresh_token();
		return parent::request( $url, $params );
	}

	function build_token_meta( $token ) {
		$meta = array(
			'refresh_token' => $token['refresh_token'],
			'expires'       => $token['expires_at'],
		);

		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta['user_id'] = (int) $response->id;

			// Now get the rest of their profile
			$profile = $this->request( $this->user_url, array( 'method' => $this->user_method ) );

			if ( ! Keyring_Util::is_error( $profile ) ) {
				// Somehow "username" can be "null" in the Strava data model, so then we use a concat of first_name + last_name
				$meta['name'] = '';
				if ( empty( $profile->username ) ) {
					if ( ! empty( $profile->firstname ) ) {
						$meta['name'] .= $profile->firstname;
					}
					if ( ! empty( $profile->lastname ) ) {
						$meta['name'] .= ' ' . $profile->lastname;
					}
					$meta['name'] = trim( $meta['name'] );
				} else {
					$meta['name'] = $profile->username;
				}
				$meta['first_name'] = $profile->firstname;
				$meta['last_name']  = $profile->lastname;
				$meta['picture']    = $profile->profile;
				$meta['first_date'] = $profile->created_at; // Capture the athlete's profile creation date for later use, eg: in keyring-social-importers
			}

			return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $profile, $this );
		}
		return array();
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function maybe_refresh_token() {
		// Request a new token, using the refresh_token
		$token = $this->get_token();
		$meta  = $token->get_meta();
		if ( empty( $meta['refresh_token'] ) ) {
			return false;
		}

		// Don't refresh if token is valid
		if ( ! $token->is_expired( 20 ) ) {
			return;
		}

		$response = wp_remote_post(
			$this->refresh_url,
			array(
				'method' => $this->refresh_method,
				'body'   => array(
					'client_id'     => $this->key,
					'client_secret' => $this->secret,
					'refresh_token' => $meta['refresh_token'],
					'grant_type'    => 'refresh_token',
				),
			)
		);

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$return          = json_decode( wp_remote_retrieve_body( $response ) );
		$meta['expires'] = $return->expires_at;

		// Build access token
		$access_token = new Keyring_Access_Token(
			$this->get_name(),
			$return->access_token,
			$meta,
			$this->token->unique_id
		);

		// Store the updated access token
		$access_token = apply_filters( 'keyring_access_token', $access_token, (array) $return );
		$id           = $this->store->update( $access_token );

		// And switch to using it
		$this->set_token( $access_token );
	}

	function test_connection() {
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Strava', 'init' ) );
