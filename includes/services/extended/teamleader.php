<?php

/**
 * Teamleader service definition for Keyring.
 * https://developer.teamleader.eu/#/introduction/authentication/oauth-2
 */

class Keyring_Service_Teamleader extends Keyring_Service_OAuth2 {
	const NAME  = 'teamleader';
	const LABEL = 'Teamleader';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_teamleader_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_teamleader_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://focus.teamleader.eu/oauth2/authorize', 'GET' );
		$this->set_endpoint( 'access_token', 'https://focus.teamleader.eu/oauth2/access_token', 'POST' );
		$this->set_endpoint( 'refresh', 'https://focus.teamleader.eu/oauth2/access_token', 'POST' );
		$this->set_endpoint( 'self', 'https://api.focus.teamleader.eu/users.me', 'GET' );
		$this->set_endpoint( 'test', 'https://api.focus.teamleader.eu/users.me', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->authorization_header = 'Bearer';

		// Strip nonces, since you can't save them in your app config, and Teamleader is strict about redirect_uris
		// Can also only return you to an HTTPS address
		$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url );

		// Teamleader ignores our redirect_uri, and just redirects back to a static URI
		add_action( 'pre_keyring_teamleader_verify', array( $this, 'redirect_incoming_verify' ) );
	}

	function request( $url, array $params = array() ) {
		$this->maybe_refresh_token();
		return parent::request( $url, $params );
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
		$meta['refresh_token'] = $return->refresh_token;
		$meta['expires'] = time() + $return->expires_in;

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

	function redirect_incoming_verify( $request ) {
		if ( ! isset( $request['kr_nonce'] ) ) {
			// First request, from Teamleader. Nonce it and move on.
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

	function basic_ui_intro() {
		/* translators: %$1s: Teamleader developers URL, %2s: the redirect URL to verify the connection */
		echo '<p>' . sprintf( __( 'You will need to create a Developer account, and <a href="%1$s">set up a Teamleader integration</a> (that is what they call Marketplace integration). Make sure you select appropriate permissions as well.', 'keyring' ), 'https://marketplace.focus.teamleader.eu/eu/en/build', Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've set that up, copy your <strong>Client ID</strong> value into the <strong>API Key</strong> field, and the <strong>Client Secret</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for eamleader).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$meta = array(
			'refresh_token' => $token['refresh_token'],
			'expires'       => time() + $token['expires_in'],
		);
		
		$token = new Keyring_Access_Token( $this->get_name(), $token['access_token'], array() );
		$this->set_token( $token );
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( Keyring_Util::is_error( $res ) ) {
			$meta = array();
		} else {
			$meta['user_id'] = $res->data->id;
			$meta['first_name'] = $res->data->first_name;
			$meta['last_name'] = $res->data->last_name;
			$meta['email'] = $res->data->email;
			$meta['function'] = $res->data->function;
			$meta['picture'] = $res->data->avatar_url;
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {		
		$response = $this->request( $this->test_url, array( 'method' => $this->test_method ) );

		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Teamleader', 'init' ) );
