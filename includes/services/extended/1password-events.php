<?php

/**
 * 1Password Events Service for Keyring.
 *
 * 1Password Events API: https://developer.1password.com/docs/events-api
 * 
 * Response codes: 	200 Returns an `ItemUsage` response object
 * 					400 Bad request
 * 					401 Unauthorized access
 * 					500 Internal server error
 * 
 * API requires a bearer token and a Cursor or ResetCursor object
 */

// @TODO
// Create our own basic UI for entering and managing key/secret
// allowing for more than one 1Password account to be configured

class Keyring_Service_1Password_Events extends Keyring_Service_Simple_Token {
	const NAME        = 'onepasswordevents';
	const LABEL       = '1Password Events';

	function __construct() {
		parent::__construct();

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->token = $creds['token'];
		}

		$this->authorization_header    = 'Bearer';

		$this->set_endpoint( 'verify', 'https://events.1password.com/api/v1/itemusages', 'POST' );

		// 1Password requires either a Cursor or ResetCursor object
		add_filter( 'keyring_onepasswordevents_verify_token_post_params', array( $this, 'verify_token_post_params' ) );

		// Add intro UI specific to 1Password Events
		add_filter( 'keyring_onepasswordevents_request_ui_intro', array( $this, 'request_ui_intro' ) );

		add_filter( 'keyring_' . $this->get_name() . '_request_token_params', array( $this, 'request_token_params' ) );
	}

	function verify_token_post_params( $params ) {

		$start_time = (new \DateTime());

		$payload = array(
			"limit" => 1,
			"start_time" =>	$start_time->format('Y-m-d\TH:i:s\Z')
		);
		
		$params = json_encode($payload);
		
		return $params;
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__1PASSWORD_EVENTS_KEY' )
		) {
			return array(
				'token'       => constant( 'KEYRING__1PASSWORD_EVENTS_KEY' ),
			);
		} else {
			return null;
		}
	}

	// The 1Password Events API doesn't offer us anything useful to store in token meta 
	// so we don't make a request here, but we manually specify a 1Password icon for the Keyring UI 
	function build_token_meta( $token ) {
		Keyring_Util::debug( 'building token meta' );

		$meta = array(
			'picture' => 'https://1password.com/apple-touch-icon.png'
		);

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, null, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function request_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'To connect to 1Password, you\'ll need to create an "Events Reporting Integration" at <a href="%s">%s</a>.', 'keyring' ), 'https://start.1password.com/integrations/events_reporting/create?type=other', 'https://start.1password.com/integrations/events_reporting/create?type=other' ) . '</p>';
	}

	// Extends UI for entering a new token to allow for a nickname field
    function request_ui() {

		// Common Header
		echo '<div class="wrap">';
		echo '<h2>' . __( 'Account Details', 'keyring' ) . '</h2>';

		// Handle errors
		if ( isset( $_GET['error'] ) ) {
			echo '<div id="keyring-admin-errors" class="updated"><ul>';
			switch ( $_GET['error'] ) {
				case 'not-200':
					echo '<li>' . __( 'Your token could not be verified, please try again.', 'keyring' ) . '</li>';
					break;
				case 'empty':
					echo '<li>' . __( 'Please make sure you enter token and token name.', 'keyring' ) . '</li>';
					break;
			}
			echo '</ul></div>';
		}
		echo apply_filters( 'keyring_' . $this->get_name() . '_request_ui_intro', '' );

        // Output basic form for storing a token with a nickname, action is "verify"
		/* translators: service name */
		echo '<p>' . sprintf( __( 'Enter your token for accessing <strong>%s</strong>:', 'keyring' ), $this->get_label() ) . '</p>';
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
        echo '<input type="hidden" name="action" value="verify" />';
		wp_nonce_field( 'keyring-verify', 'kr_nonce', false );
		wp_nonce_field( 'keyring-verify-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'Token', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="token" value="" id="token" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Nickname', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="name" value="" id="name" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Verify Details', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url( null, array( 'action' => 'services' ) ) ) . '" class="submitdelete" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
		?><script type="text/javascript" charset="utf-8">
			jQuery( document ).ready( function() {
				jQuery( '#token' ).focus();
			} );
		</script>
		<?php
	}

	function test_connection() {
		error_log( 'testing connection' );

		$start_time = (new \DateTime())->modify('-30 minutes');

		$payload = array(
			"limit" => 500,
			"start_time" => $start_time->format('Y-m-d\TH:i:s\Z')
		  );

		$params = array(
			'method' => 'POST',
			'timeout' => 10,
			'body' => json_encode($payload)
		);

		$response = $this->request( 'https://events.1password.com/api/v1/itemusages', $params );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}

}

add_action( 'keyring_load_services', array( 'Keyring_Service_1Password_Events', 'init' ) );
