<?php

/**
 * A simple Service definition for services that just use HTTP Basic for
 * authentication. You will need to extend this and supply a verify endpoint
 * which is where the user/pass will be tested against (for a 401 response).
 *
 * @package Keyring
 */
class Keyring_Service_HTTP_Basic extends Keyring_Service {
	var $username      = null;
	var $password      = null;
	var $verify_url    = null;
	var $verify_method = null;
	var $token         = null;
	
	function __construct( $details = array() ) {
		parent::__construct( $details );
		
		if ( !empty( $details['usernmae'] ) )
			$this->username = $username;
		if ( !empty( $details['password'] ) )
			$this->password = $password;
		
		add_action( 'keyring_' . $this->get_name() . '_request_ui', array( $this, 'request_ui' ) );
	}
	
	function get_display( $token ) {
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
			echo '<ul>';
			switch ( $_GET['error'] ) {
			case '401':
				echo '<li>' . __( 'Your account details could not be confirmed, please try again.', 'keyring' ) . '</li>';
			}
			echo '</ul>';
		}
		
		echo apply_filters( 'keyring_' . $this->get_name() . '_request_ui_intro', '' );
		
		// Output basic form for collecting user/pass
		echo '<p>' . sprintf( __( 'Enter your username and password for accessing %s:', 'keyring' ), $this->get_label() ) . '</p>';
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="verify" />';
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
		$token = base64_encode( $_POST['username'] . ':' . $_POST['password'] );
		$params = array( 'headers' => array( 'Authorization' => 'Basic ' . $token ) );
		if ( 'GET' == $this->verify_method ) {
			// GET Request
			$res = wp_remote_get( $this->verify_url, $params );
		} else {
			// POST Request
			$res = wp_remote_post( $this->verify_url, $params );
		}
		
		// We will get a 401 if they entered an incorrect user/pass combo
		if ( 401 == wp_remote_retrieve_response_code( $res ) ) {
			$c = get_called_class();
			$service = $c::NAME;
			$url = Keyring_Util::admin_url(
				$c::NAME,
				array(
					'action' => 'request',
					'error' => '401',
				)
			);
			Keyring_Util::debug( $url );
			wp_safe_redirect( $url );
			exit;
		}
		
		// If we didn't get a 401, then we'll assume it's OK
		$id = $this->store_token( $token, array( 'username' => $_POST['username'] ) );
		$this->verified( $id );
	}
	
	function request( $url, $params = array() ) {
		if ( $this->requires_token() && empty( $this->token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );

		$params['headers'] = array( 'Authorization' => 'Basic ' . $this->token );
		if ( 'GET' == strtoupper( $params['method'] ) ) {
			$res = wp_remote_get( $url, $params );
		} else {
			$res = wp_remote_post( $url, $params );
		}
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			return wp_remote_retrieve_body( $res );
		} else {
			return new Keyring_Error( 'keyring-request-error', $res );
		}
	}
}
