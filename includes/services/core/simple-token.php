<?php

/**
 * A simple Service definition for services that need to store a simple token. 
 * You will need to extend this and supply a verify endpoint
 * which is where the token will be tested against (a 200 response is considered successful).
 *
 * @package Keyring
 *
 */
class Keyring_Service_Simple_Token extends Keyring_Service {
    protected $verify_method = null;
	protected $verify_url    = null;
	protected $token         = null;

    function __construct() {
		parent::__construct();

		// If we're not in headless mode, add request_ui for storing a new token
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_' . $this->get_name() . '_request_ui', array( $this, 'request_ui' ) );
		}
	}

	function get_display( Keyring_Access_Token $token ) {
		$meta = $token->get_meta();
		return $meta['name'];
	}

	// Minimal UI for entering a new token, can be overriden by a Service, eg: to store additional metadata for the token
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
					echo '<li>' . __( 'Please make sure you enter a token.', 'keyring' ) . '</li>';
					break;
			}
			echo '</ul></div>';
		}
		echo apply_filters( 'keyring_' . $this->get_name() . '_request_ui_intro', '' );

        // Output basic form for storing a token, action is "verify"
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

	// Unused in this class, but maintained for consistency
    function request_token() {
		return;
	}

	// Handler for both request and manage UI's
	function verify_token() {
		Keyring_Util::debug( 'verifying token' );
		if ( ! isset( $_REQUEST['nonce'] ) || ! wp_verify_nonce( $_REQUEST['nonce'], 'keyring-verify-' . $this->get_name() ) ) {
			Keyring::error( __( 'Invalid/missing verification nonce.', 'keyring' ) );
			exit;
		}

		if ( ! strlen( $_POST['token'] ) ) {
			$url = Keyring_Util::admin_url(
				$this->get_name(),
				array(
					'action'   => 'request',
					'error'    => 'empty',
					'kr_nonce' => wp_create_nonce( 'keyring-request' ),
				)
			);
			Keyring_Util::debug( $url );
			wp_safe_redirect( $url );
			exit;
		}

		$token = new Keyring_Access_Token(
			$this->get_name(),
			trim( $_POST['token'] )
		);
		$this->set_token( $token );

		// @TODO verify_url and verify_method should be defined in a service file, but could be undefined and we should check for that 
		$res = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );

		// Add checking here...we should get a not-200 if the token is invalid
		// will then return a Keyring_Error
		if ( Keyring_Util::is_error( $res ) ) {
			$url = Keyring_Util::admin_url(
				$this->get_name(),
				array(
					'action'   => 'request',
					'error'		=> 'not-200',
					'kr_nonce' => wp_create_nonce( 'keyring-request' ),
				)
			);
			Keyring_Util::debug( $url );
			wp_safe_redirect( $url );
			exit;
		}

		// Save token meta, combining "name" from token entry with meta provided by calling service
		$meta = array_merge(
			array( 'name' => trim( $_POST['name'] ) ),
			$this->build_token_meta( $token )
		);
		Keyring_Util::debug( print_r( $meta, true ) );

		$access_token = new Keyring_Access_Token(
			$this->get_name(),
			$token,
			$meta
		);
		Keyring_Util::debug( print_r( $access_token, true ) );
		
		$access_token = apply_filters( 'keyring_access_token', $access_token, array() );

		$id = $this->store_token( $access_token );
		$this->verified( $id, $access_token );
	}
    
	function request( $url, array $params = array() ) {
		Keyring_Util::debug( 'making request' );
		if ( $this->requires_token() && empty( $this->token ) ) {
			Keyring_Util::debug( 'no token' );
			return new Keyring_Error( 'keyring-request-error', __( 'No token', 'keyring' ) );
		}

		$token = $this->token ? $this->token : null;

		if ( ! is_null( $token ) ) {
			if ( $this->authorization_header ) {
				// type can be OAuth, Bearer, ...
				$params['headers']['Authorization'] = $this->authorization_header . ' ' . (string) $token;
			} else {
				$url = add_query_arg( array( $this->authorization_parameter => urlencode( (string) $token ) ), $url );
			}
		}

		// Default to GET, but allow Service to override
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

		Keyring_Util::debug( "Basic Token $method $url" );

		switch ( strtoupper( $method ) ) {
			case 'GET':
				$res = wp_remote_get( $url, $params );
				break;

			case 'POST':
				// @TODO simplify this
				$res = wp_remote_post(
					$url,
					array(
						'method' 	=> $method,
						'headers'	=> array(
							'Authorization' => $params['headers']['Authorization'],
							'Content-Type'  => 'application/json',
						),
						'body' 		=> apply_filters( 'keyring_' . $this->get_name() . '_verify_token_post_params', $params ),
					)
				);
				break;

			default:
				Keyring::error( __( 'Unsupported method specified for verify_token.', 'keyring' ) );
				exit;
		}

		Keyring_Util::debug( $res );
		$this->set_request_response_code( wp_remote_retrieve_response_code( $res ) );
		if ( '2' === substr( wp_remote_retrieve_response_code( $res ), 0, 1 ) ) {
			if ( $raw_response ) {
				return wp_remote_retrieve_body( $res );
			} elseif ( '' === wp_remote_retrieve_body( $res ) ) {
				return wp_remote_retrieve_headers( $res );
			} else {
				return $this->parse_response( wp_remote_retrieve_body( $res ) );
			}
		} else {
			return new Keyring_Error( 'keyring-request-error', $res );
		}
	}

	/**
	 * Generally expecting JSON. You can still override this
	 * per service if you like, but by default we'll assume JSON.
	 */
	function parse_response( $response ) {
		return json_decode( $response );
	}
}