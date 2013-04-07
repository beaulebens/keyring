<?php

/**
 * Yahoo service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Yahoo extends Keyring_Service_OAuth1 {
	const NAME  = 'yahoo';
	const LABEL = 'Yahoo! Updates';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_yahoo_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_yahoo_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'request_token', 'https://api.login.yahoo.com/oauth/v2/get_request_token', 'GET' );
		$this->set_endpoint( 'authorize',     'https://api.login.yahoo.com/oauth/v2/request_auth',      'GET' );
		$this->set_endpoint( 'access_token',  'https://api.login.yahoo.com/oauth/v2/get_token',         'POST' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( "To connect to Yahoo!, you need to <a href='https://developer.apps.yahoo.com/dashboard/createKey.html'>Create a new project</a>. Make sure you set the <strong>Access Scope</strong> to <strong>This app requires access to private user data</strong>. When you select that, you will be asked for an <strong>Application Domain</strong>, which should probably be set to <code>http://%s</code>. Which APIs you request access for will depend on how Keyring will be used on this site. Common ones will be <strong>Contacts</strong>, <strong>Social Directory</strong>, <strong>Status</strong>, and <strong>Updates</strong>.", 'keyring' ), $_SERVER['HTTP_HOST'] ) . '</p>';
		echo '<p>' . __( "Once you've created your project, copy and paste your <strong>Consumer key</strong> and <strong>Consumer secret</strong> (from under the <strong>Authentication Information: OAuth</strong> section of your app's details) into the boxes below. You don't need an App ID for Yahoo!.", 'keyring' ) . '</p>';
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		$expires = isset( $token['oauth_expires_in'] ) ? gmdate( 'Y-m-d H:i:s', time() + $token['oauth_expires_in'] ) : 0;

		$this->set_token(
			new Keyring_Access_Token(
				'yahoo',
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		// Get user profile information
		$response = $this->request( "http://social.yahooapis.com/v1/user/{$token['xoauth_yahoo_guid']}/profile?format=json" );

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$this->person = $response->profile;
			$meta = array(
				'user_id' => $token['xoauth_yahoo_guid'],
				'name'    => $this->person->nickname,
				'picture' => $this->person->image->imageUrl,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'yahoo', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token$token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
		$this->maybe_refresh_token();

		$guid = $this->token->get_meta( 'external_id' );

		$res = $this->request( 'http://social.yahooapis.com/v1/user/' . $guid . '/profile?format=json' );
		if ( !Keyring_Util::is_error( $res ) )
			return true;

		return $res;
	}

	function maybe_refresh_token() {
		global $wpdb;

		if ( empty( $this->token->token ) || empty( $this->token->token->tokenExpires ) )
			return;

		if ( $this->token->token->tokenExpires && $this->token->token->tokenExpires < time() ) {
			$api_url  = 'https://api.login.yahoo.com/oauth/v2/get_token';
			$api_url .= '?oauth_session_handle=' . $this->token->token->sessionHandle;

			$refresh = $this->request( $api_url, array(
				'method'       => 'GET',
				'raw_response' => true,
			) );

			if ( !Keyring_Util::is_error( $refresh ) ) {
				$token = $this->parse_access_token( $refresh );

				// Fake request token
				global $keyring_request_token;
				$keyring_request_token = new Keyring_Request_Token(
					$this->get_name(),
					array()
				);

				// Build (real) access token
				$access_token = new Keyring_Access_Token(
					$this->get_name(),
					new OAuthToken(
						$token['oauth_token'],
						$token['oauth_token_secret']
					),
					$this->build_token_meta( $token ),
					$this->token->unique_id
				);

				// Store the updated access token
				$access_token = apply_filters( 'keyring_access_token', $access_token, $token );
				$id = $this->store->update( $access_token );

				// And switch to using it
				$this->set_token( $access_token );
			}
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Yahoo', 'init' ) );
