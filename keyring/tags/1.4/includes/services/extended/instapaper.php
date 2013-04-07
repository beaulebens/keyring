<?php

/**
 * Instapaper uses xAuth, just to be difficult.
 */

class Keyring_Service_Instapaper extends Keyring_Service_OAuth1 {
	const NAME  = 'instapaper';
	const LABEL = 'Instapaper';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret, and the request UI for user/pass
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_instapaper_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_instapaper_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
			add_action( 'keyring_instapaper_request_ui', array( $this, 'request_ui' ) );
		}

		$this->authorization_header = true;

		$this->set_endpoint( 'access_token', 'https://www.instapaper.com/api/1/oauth/access_token',         'POST' );
		$this->set_endpoint( 'verify',       'https://www.instapaper.com/api/1/account/verify_credentials', 'POST' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	function basic_ui_intro() {
		echo '<p>' . __( "To use the Instapaper API, you need to get manually approved. <a href='http://www.instapaper.com/main/request_oauth_consumer_token'>Apply here</a>, then wait for a reply email.", 'keyring' ) . '</p>';
		echo '<p>' . __( "Once you get approved, you'll get an email back with your details. Copy the <strong>OAuth consumer key</strong> value into the <strong>API Key</strong> field, and the <strong>OAuth consumer secret</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Instapaper).", 'keyring' ) . '</p>';
	}

	/**
	 * Mostly duplicated from HTTP Basic
	 */
	function request_ui() {
		// Common Header
		echo '<div class="wrap">';
		screen_icon( 'ms-admin' );
		echo '<h2>' . __( 'Account Details', 'keyring' ) . '</h2>';

		// Handle errors
		if ( isset( $_GET['error'] ) ) {
			echo '<div id="keyring-admin-errors" class="updated"><ul>';
			switch ( $_GET['error'] ) {
			case '401':
				echo '<li>' . __( 'Your account details could not be confirmed, please try again.', 'keyring' ) . '</li>';
				break;
			case 'empty':
				echo '<li>' . __( 'Please make sure you enter a username and password.', 'keyring' ) . '</li>';
				break;
			}
			echo '</ul></div>';
		}

		// Even though it doesn't make too much sense, we support request tokens in HTTP Basic
		// to ensure consistency with other services
		$request_token = new Keyring_Request_Token(
			$this->get_name(),
			array(),
			apply_filters(
				'keyring_request_token_meta',
				array(
					'for' => isset( $_REQUEST['for'] ) ? (string) $_REQUEST['for'] : false
				),
				$this->get_name(),
				array() // no token
			)
		);
		$request_token     = apply_filters( 'keyring_request_token', $request_token, $this );
		$request_token_id  = $this->store_token( $request_token );
		Keyring_Util::debug( 'xAuth/Instapaper Stored Request token ' . $request_token_id );

		echo apply_filters( 'keyring_' . $this->get_name() . '_request_ui_intro', '' );

		// Output basic form for collecting user/pass
		echo '<p>' . sprintf( __( 'Enter your username (or email address) and password for accessing <strong>%s</strong>:', 'keyring' ), $this->get_label() ) . '</p>';
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="verify" />';
		echo '<input type="hidden" name="state" value="' . esc_attr( $request_token_id ) . '" />';
		wp_nonce_field( 'keyring-verify', 'kr_nonce', false );
		wp_nonce_field( 'keyring-verify-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'Email address', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="username" value="" id="username" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Password', 'keyring' ) . '</th>';
		echo '<td><input type="password" name="password" value="" id="password" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Verify Details', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_attr( $_SERVER['HTTP_REFERER'] ) . '" class="submitdelete" id="logincancel" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
		?><script type="text/javascript" charset="utf-8">
			jQuery( document ).ready( function() {
				jQuery( '#username' ).focus();
			} );
		</script><?php
	}

	function request_token() { }

	function verify_token() {
		if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-verify-' . $this->get_name() ) ) {
			Keyring::error( __( 'Invalid/missing verification nonce.', 'keyring' ) );
			exit;
		}

		// Load up the request token that got us here and globalize it
		if ( $_REQUEST['state'] ) {
			global $keyring_request_token;
			$state = (int) $_REQUEST['state'];
			$keyring_request_token = $this->store->get_token( array( 'id' => $state, 'type' => 'request' ) );
			Keyring_Util::debug( 'xAuth/Instapaper Loaded Request Token ' . $_REQUEST['state'] );
			Keyring_Util::debug( $keyring_request_token );

			// Remove request token, don't need it any more.
			$this->store->delete( array( 'id' => $state, 'type' => 'request' ) );
		}

		if ( !strlen( $_POST['username'] ) ) {
			$url = Keyring_Util::admin_url(
				$this->get_name(),
				array(
					'action' => 'request',
					'error' => 'empty',
					'kr_nonce' => wp_create_nonce( 'keyring-request' )
				)
			);
			Keyring_Util::debug( $url );
			wp_safe_redirect( $url );
			exit;
		}

		$body = array(
			'x_auth_mode'     => 'client_auth',
			'x_auth_password' => $_POST['password'],
			'x_auth_username' => $_POST['username'],
		);
		ksort( $body );
		$this->set_token( new Keyring_Access_Token( $this->get_name(), null, array() ) );
		$res = $this->request( $this->access_token_url, array( 'method' => $this->access_token_method, 'raw_response' => true, 'body' => $body ) );
		Keyring_Util::debug( 'OAuth1 Access Token Response' );
		Keyring_Util::debug( $res );

		// We will get a 401 if they entered an incorrect user/pass combo. ::request
		// will then return a Keyring_Error
		if ( Keyring_Util::is_error( $res ) ) {
			$url = Keyring_Util::admin_url(
				$this->get_name(),
				array(
					'action'   => 'request',
					'error'    => '401',
					'kr_nonce' => wp_create_nonce( 'keyring-request' )
				)
			);
			Keyring_Util::debug( $url );
			wp_safe_redirect( $url );
			exit;
		}

		parse_str( $res, $token );

		$meta = array_merge( array( 'username' => $_POST['username'] ), $this->build_token_meta( $token ) );

		$access_token = new Keyring_Access_Token(
			$this->get_name(),
			new OAuthToken( $token['oauth_token'], $token['oauth_token_secret'] ),
			$meta
		);
		$access_token = apply_filters( 'keyring_access_token', $access_token );

		// If we didn't get a 401, then we'll assume it's OK
		$id = $this->store_token( $access_token );
		$this->verified( $id, $keyring_request_token );
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'    => $response[0]->user_id,
				'username'   => $response[0]->username,
				'name'       => $response[0]->username,
				'_classname' => get_called_class(),
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'instapaper', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'username' );
	}

	function test_connection() {
			$response = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
			if ( !Keyring_Util::is_error( $response ) )
				return true;

			return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Instapaper', 'init' ) );
