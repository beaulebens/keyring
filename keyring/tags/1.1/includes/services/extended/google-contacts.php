<?php

/**
 * Google (Contacts) service definition for Keyring.
 * Contacts API: https://developers.google.com/google-apps/contacts/v3/
 * OAuth implementation: https://developers.google.com/accounts/docs/OAuth2WebServer
 * App registration: https://code.google.com/apis/console/
 */

class Keyring_Service_GoogleContacts extends Keyring_Service_OAuth2 {
	const NAME        = 'google-contacts';
	const LABEL       = 'Google Contacts';
	const SCOPE       = 'https://www.google.com/m8/feeds https://www.googleapis.com/auth/userinfo.profile'; // See https://developers.google.com/google-apps/contacts/v3/#authorizing_requests_with_oauth_20
	const API_VERSION = '3.0';

	var $self_url     = '';
	var $self_method  = '';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_google-contacts_manage_ui', array( $this, 'basic_ui' ) );

		// Set scope
		add_filter( 'keyring_google-contacts_request_token_params', array( $this, 'request_token_params' ) );

		// Handle Google's annoying limitation of not allowing us to redirect to a dynamic URL
		add_action( 'pre_keyring_google-contacts_verify', array( $this, 'redirect_incoming_verify' ) );

		$this->set_endpoint( 'authorize',    'https://accounts.google.com/o/oauth2/auth',     'GET'  );
		$this->set_endpoint( 'access_token', 'https://accounts.google.com/o/oauth2/token',    'POST' );
		$this->set_endpoint( 'self',         'https://www.googleapis.com/oauth2/v1/userinfo', 'GET' );

		if ( defined( 'KEYRING__GOOGLECONTACTS_KEY' ) && defined( 'KEYRING__GOOGLECONTACTS_SECRET' ) ) {
			$this->key = KEYRING__GOOGLECONTACTS_KEY;
			$this->secret = KEYRING__GOOGLECONTACTS_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->key = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header = 'Bearer'; // Oh, you

		// Need to reset the callback because Google is very strict about where it sends people
		if ( !empty( $creds['redirect_uri'] ) )
			$this->callback_url = $creds['redirect_uri']; // Allow user to manually enter a redirect URI
		else
			$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url ); // At least strip nonces, since you can't save them in your app config
	}

	function request_token_params( $params ) {
		$params['scope'] = self::SCOPE;
		return $params;
	}

	function redirect_incoming_verify( $request ) {
		if ( !isset( $request['kr_nonce'] ) ) {
			// First request, from Google. Nonce it and move on.
			$kr_nonce = wp_create_nonce( 'keyring-verify' );
			$nonce = wp_create_nonce( 'keyring-verify-' . $this->get_name() );
			wp_safe_redirect(
				Keyring_Util::admin_url(
					$this->get_name(),
					array(
						'action' => 'verify',
						'kr_nonce' => $kr_nonce,
						'nonce' => $nonce,
						'code' => $request['code'], // Auth code from successful response (maybe)
					)
				)
			);
			exit;
		}
	}

	function build_token_meta( $token ) {
		$meta = array();
		if ( !$token )
			return $meta;

		$token = new Keyring_Token( $this->get_name(), new OAuthToken( $token['access_token'], '' ), array() );
		$this->set_token( $token );
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( !Keyring_Util::is_error( $res ) ) {
			$meta = array(
				'user_id' => $res->id,
				'name'    => $res->name,
				'url'     => $res->link,
				'picture' => $res->picture,
			);
		}
		return $meta;
	}

	function get_display( Keyring_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function request( $url, array $params = array() ) {
		// add header (version), required for all requests
		$params['headers']['GData-Version'] = self::API_VERSION;

		return parent::request( $url, $params );
	}

	// Minor modifications from Keyring_Service::basic_ui
	function basic_ui() {
		if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-manage-' . $this->get_name() ) )
			wp_die( __( 'Invalid/missing management nonce.', 'keyring' ) );

		// Common Header
		echo '<div class="wrap">';
		screen_icon( 'ms-admin' );
		echo '<h2>' . __( 'Keyring Service Management', 'keyring' ) . '</h2>';
		echo '<p><a href="' . Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) . '">' . __( '&larr; Back', 'keyring' ) . '</a></p>';
		echo '<h3>' . sprintf( __( '%s API Credentials', 'keyring' ), esc_html( $this->get_label() ) ) . '</h3>';

		// Handle actually saving credentials
		if ( isset( $_POST['api_key'] ) && isset( $_POST['api_secret'] ) ) {
			// Store credentials against this service
			$this->update_credentials( array(
				'key' => stripslashes( $_POST['api_key'] ),
				'secret' => stripslashes( $_POST['api_secret'] ),
				'redirect_uri' => stripslashes( $_POST['redirect_uri'] ),
			) );
			echo '<div class="updated"><p>' . __( 'Credentials saved.', 'keyring' ) . '</p></div>';
		}

		$api_key = $api_secret = $redirect_uri = '';
		if ( $creds = $this->get_credentials() ) {
			$api_key = $creds['key'];
			$api_secret = $creds['secret'];
			$redirect_uri = $creds['redirect_uri'];
		}

		echo apply_filters( 'keyring_' . $this->get_name() . '_basic_ui_intro', '' );

		// Output basic form for collecting key/secret
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="manage" />';
		wp_nonce_field( 'keyring-manage', 'kr_nonce', false );
		wp_nonce_field( 'keyring-manage-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'Client ID', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="api_key" value="' . esc_attr( $api_key ) . '" id="api_key" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Client secret', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="api_secret" value="' . esc_attr( $api_secret ) . '" id="api_secret" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Redirect URI', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="redirect_uri" value="' . esc_attr( $redirect_uri ) . '" id="redirect_uri" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Save Changes', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url() ) . '" class="submitdelete" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_GoogleContacts', 'init' ) );
