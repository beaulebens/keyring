<?php

/**
 * A simple Service definition for services that just use HTTP Basic for
 * authentication. You will need to extend this and supply a verify endpoint
 * which is where the user/pass will be tested against (for a 401 response).
 *
 * @package Keyring
 */
class Keyring_Service_HTTP_Basic extends Keyring_Service {
	protected $username      = null;
	protected $password      = null;
	protected $verify_url    = null;
	protected $verify_method = null;
	protected $token         = null;
	
	function __construct() {
		parent::__construct();
		
		add_action( 'keyring_' . $this->get_name() . '_request_ui', array( $this, 'request_ui' ) );
	}
	
	function get_display( Keyring_Token $token ) {
		$meta = $token->get_meta();
		return $meta['username'];
	}
	
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
		
		echo apply_filters( 'keyring_' . $this->get_name() . '_request_ui_intro', '' );
		
		// Output basic form for collecting user/pass
		echo '<p>' . sprintf( __( 'Enter your username and password for accessing %s:', 'keyring' ), $this->get_label() ) . '</p>';
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="verify" />';
		wp_nonce_field( 'keyring-verify', 'kr_nonce', false );
		wp_nonce_field( 'keyring-verify-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'Username', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="username" value="" id="username" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Password', 'keyring' ) . '</th>';
		echo '<td><input type="password" name="password" value="" id="password" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Verify Details', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url() ) . '" class="submitdelete" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
		?><script type="text/javascript" charset="utf-8">
			jQuery( document ).ready( function() {
				jQuery( '#username' ).focus();
			} );
		</script><?php
	}
	
	function request_token() {
		return;
	}
	
	function verify_token() {
		if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-verify-' . $this->get_name() ) )
			wp_die( __( 'Invalid/missing verification nonce.', 'keyring' ) );

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
			
		
		$token = base64_encode( $_POST['username'] . ':' . $_POST['password'] );
		$this->set_token( new Keyring_Token( $this->get_name(), $token, array() ) );
		$res = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		
		// We will get a 401 if they entered an incorrect user/pass combo. ::request
		// will then return a Keyring_Error
		if ( Keyring_Util::is_error( $res ) ) {
			$url = Keyring_Util::admin_url(
				$this->get_name(),
				array(
					'action' => 'request',
					'error' => '401',
					'kr_nonce' => wp_create_nonce( 'keyring-request' )
				)
			);
			Keyring_Util::debug( $url );
			wp_safe_redirect( $url );
			exit;
		}
		
		if ( method_exists( $this, 'custom_verify_token' ) )
			$this->custom_verify_token( $token );
		
		$meta = array_merge( array( 'username' => $_POST['username'] ), $this->build_token_meta( $token ) );
		
		// If we didn't get a 401, then we'll assume it's OK
		$id = $this->store_token( $token, $meta );
		$this->verified( $id );
	}
	
	function request( $url, array $params = array() ) {
		if ( $this->requires_token() && empty( $this->token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );
		
		if ( $this->requires_token() )
			$params['headers'] = array( 'Authorization' => 'Basic ' . $this->token );
		
		$method = 'GET';
		if ( isset( $params['method'] ) ) {
			$method = strtoupper( $params['method'] );
			unset( $params['method'] );
		}
		
		$raw_response = false;
		if ( isset( $params['raw_response'] ) ) {
			$raw_response = (bool) $params['raw_response'];
			unset( $params['raw_response'] );
		}
		
		Keyring_Util::debug( "HTTP Basic $method $url" );
		Keyring_Util::debug( $params );
		
		switch ( strtoupper( $method ) ) {
		case 'GET':
			$res = wp_remote_get( $url, $params );
			break;

		case 'POST':
			$res = wp_remote_post( $url, $params );
			break;

		default:
			wp_die( __( 'Unsupported method specified for verify_token.', 'keyring' ) );
			exit;
		}

		Keyring_Util::debug( $res );
		
		if ( 200 == wp_remote_retrieve_response_code( $res ) || 201 == wp_remote_retrieve_response_code( $res ) ) {
			if ( $raw_response )
				return wp_remote_retrieve_body( $res );
			else
				return $this->parse_response( wp_remote_retrieve_body( $res ) );
		} else {
			return new Keyring_Error( 'keyring-request-error', $res );
		}
	}
}
