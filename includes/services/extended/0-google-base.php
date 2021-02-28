<?php

/**
 * Google base service definition for Keyring. Extend to specific services
 *
 * OAuth implementation: https://developers.google.com/identity/protocols/OAuth2WebServer
 * App registration: https://console.developers.google.com/
 * Developer Console: https://console.developers.google.com/apis/dashboard
 *
 * Make sure you implement _get_credentials() and set the required CONSTs (especially SCOPE ) in child classes.
 * See google-mail.php for an example.
 */

class Keyring_Service_GoogleBase extends Keyring_Service_OAuth2 {
	var $api_label = '';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_' . $this->get_name() . '_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_' . $this->get_name() . '_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://accounts.google.com/o/oauth2/v2/auth', 'GET' );
		$this->set_endpoint( 'access_token', 'https://www.googleapis.com/oauth2/v4/token', 'POST' );
		$this->set_endpoint( 'refresh', 'https://www.googleapis.com/oauth2/v4/token', 'POST' );
		$this->set_endpoint( 'userinfo', 'https://www.googleapis.com/oauth2/v3/userinfo', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->redirect_uri = $creds['redirect_uri'];
			$this->key          = $creds['key'];
			$this->secret       = $creds['secret'];
		}

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;

		// Need to reset the callback because Google is very strict about where it sends people
		if ( ! empty( $creds['redirect_uri'] ) ) {
			$this->callback_url = $creds['redirect_uri']; // Allow user to manually enter a redirect URI
		} else {
			$this->callback_url = remove_query_arg( array( 'nonce', 'kr_nonce' ), $this->callback_url ); // At least strip nonces, since you can't save them in your app config
		}

		add_filter( 'keyring_' . $this->get_name() . '_request_token_params', array( $this, 'request_token_params' ) );
		add_action( 'pre_keyring_' . $this->get_name() . '_verify', array( $this, 'redirect_incoming_verify' ) );
	}

	function basic_ui_intro() {
		$class = get_called_class();

		/* translators: url */
		echo '<p>' . sprintf( __( "Google controls access to all of their APIs through their API Console. <a href='%s'>Go to the Library page in the console</a> and click the <strong>Select a project</strong> dropdown next to the logo in the upper left of the screen. Click the <strong>plus icon</strong> to create a new project. Enter a name and then click <strong>Create</strong>.", 'keyring' ), 'https://console.developers.google.com/apis/library' ) . '</p>';
		/* translators: %s: The name of the service being connected */
		echo '<p>' . sprintf( __( 'Now you need to enable the %s and setup your OAuth credentials.', 'keyring' ), $class::LABEL ) . '</p>';
		echo '<ol>';
		echo '<li>' . __( 'Select your project from the project dropdown.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Click <strong>Library</strong> in the menu on the left.', 'keyring' ) . '</li>';
		/* translators: %s: The name of the service being connected */
		echo '<li>' . sprintf( __( 'Find and click <strong>%s</strong>.', 'keyring' ), $class::LABEL ) . '</li>';
		echo '<li>' . __( 'Next to the heading, click <strong>Enable</strong>.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Click the blue button labelled <strong>Create credentials</strong>.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Click <strong>Credential</strong> in the menu on the left.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Click the <strong>OAuth consent screen</strong> menu item.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'You must enter a <strong>Product name</strong>, but you can skip the logo and home page URL.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Click Save.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Click the <strong>Create credentials</strong> button and select <strong>OAuth client ID</strong>.', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Select <strong>Web application</strong> and enter a relevant name or just use the default.', 'keyring' ) . '</li>';
		/* translators: %s: The user's domain name */
		echo '<li>' . sprintf( __( 'For the <strong>Authorized JavaScript Origins</strong>, enter the URL of your domain, e.g. <code>%s</code>.', 'keyring' ), ( is_ssl() ? 'https' : 'http' ) . '://' . $_SERVER['HTTP_HOST'] ) . '</li>';
		/* translators: %s: The redirect URL to verify the connection */
		echo '<li>' . sprintf( __( 'In the <strong>Authorized Redirect URIs</strong> box, enter the URL <code>%s</code>.', 'keyring' ), Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</li>';
		echo '<li>' . __( "Click <strong>Create</strong> when you're done.", 'keyring' ) . '</li>';
		echo '</ol>';
		echo '<p>' . __( "Once you've saved your details, copy the <strong>Client ID</strong> into the <strong>Client ID</strong> field below, and the <strong>Client secret</strong> value into <strong>Client Secret</strong>. The Redirect URI box should fill itself out for you.", 'keyring' ) . '</p>';

	}

	function request_token_params( $params ) {
		$class                 = get_called_class();
		$params['prompt']      = 'consent'; // Always prompt, and get a refresh token for offline access
		$params['scope']       = $class::SCOPE;
		$params['access_type'] = $class::ACCESS_TYPE;
		return $params;
	}

	// Need to potentially refresh token before each request
	function request( $url, array $params = array() ) {
		$this->maybe_refresh_token();
		return parent::request( $url, $params );
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
			'refresh_token' => $token['refresh_token'],
			'expires'       => time() + $token['expires_in'],
		);

		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->userinfo_url, array( 'method' => $this->userinfo_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			$meta['user_id'] = $response->sub;
			$meta['name']    = $response->name;
			$meta['picture'] = $response->picture;
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $response, $this );
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

	// Minor modifications from Keyring_Service::basic_ui
	function basic_ui() {
		if ( ! isset( $_REQUEST['nonce'] ) || ! wp_verify_nonce( $_REQUEST['nonce'], 'keyring-manage-' . $this->get_name() ) ) {
			Keyring::error( __( 'Invalid/missing management nonce.', 'keyring' ) );
			exit;
		}

		// Common Header
		echo '<div class="wrap">';
		echo '<h2>' . __( 'Keyring Service Management', 'keyring' ) . '</h2>';
		echo '<p><a href="' . Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) . '">' . __( '&larr; Back', 'keyring' ) . '</a></p>';
		/* translators: %s: The name of the service being connected */
		echo '<h3>' . sprintf( __( '%s API Credentials', 'keyring' ), esc_html( $this->get_label() ) ) . '</h3>';

		// Handle actually saving credentials
		if ( isset( $_POST['api_key'] ) && isset( $_POST['api_secret'] ) ) {
			// Store credentials against this service
			$this->update_credentials(
				array(
					'key'          => stripslashes( trim( $_POST['api_key'] ) ),
					'secret'       => stripslashes( trim( $_POST['api_secret'] ) ),
					'redirect_uri' => stripslashes( $_POST['redirect_uri'] ),
				)
			);
			echo '<div class="updated"><p>' . __( 'Credentials saved.', 'keyring' ) . '</p></div>';
		}

		$api_key      = '';
		$api_secret   = '';
		$redirect_uri = '';

		$creds = $this->get_credentials();
		if ( $creds ) {
			$api_key      = $creds['key'];
			$api_secret   = $creds['secret'];
			$redirect_uri = $creds['redirect_uri'];
		}

		echo apply_filters( 'keyring_' . $this->get_name() . '_basic_ui_intro', '' );

		if ( ! $redirect_uri ) {
			$redirect_uri = Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) );
		}

		// Output basic form for collecting key/secret
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="manage" />';
		wp_nonce_field( 'keyring-manage', 'kr_nonce', false );
		wp_nonce_field( 'keyring-manage-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'Client ID', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="api_key" value="' . esc_attr( $api_key ) . '" id="api_key" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Client Secret', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="api_secret" value="' . esc_attr( $api_secret ) . '" id="api_secret" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Redirect URI', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="redirect_uri" value="' . esc_attr( $redirect_uri ) . '" id="redirect_uri" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Save Changes', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url( null, array( 'action' => 'services' ) ) ) . '" class="submitdelete" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
	}

	function test_connection() {
		$res = $this->request( $this->userinfo_url, array( 'method' => $this->userinfo_method ) );
		if ( ! Keyring_Util::is_error( $res ) ) {
			return true;
		}

		return $res;
	}
}
