<?php

/**
 * Nest service definition for Keyring.
 * https://developers.nest.com/
 */

class Keyring_Service_Nest extends Keyring_Service_OAuth2 {
	const NAME  = 'nest';
	const LABEL = 'Nest';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_nest_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_nest_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://home.nest.com/login/oauth2',            'GET'  );
		$this->set_endpoint( 'access_token', 'https://api.home.nest.com/oauth2/access_token', 'POST' );
		$this->set_endpoint( 'self',         'https://developer-api.nest.com/',                'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->authorization_header = 'Bearer';

		// Nest ignores our redirect_uri, and just redirects back to a static URI
		add_action( 'pre_keyring_nest_verify', array( $this, 'redirect_incoming_verify' ) );
	}

	function redirect_incoming_verify( $request ) {
		if ( ! isset( $request['kr_nonce'] ) ) {
			// First request, from Pinterest. Nonce it and move on.
			$kr_nonce = wp_create_nonce( 'keyring-verify' );
			$nonce = wp_create_nonce( 'keyring-verify-' . $this->get_name() );
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
		echo '<p>' . sprintf( __( 'You will need to create a Developer account, and <a href="%1$s">set up a Nest Product</a> (that is what they call apps). The most important setting is the <strong>Redirect URI</strong>, which should be set to <code>%2$s</code>. Make sure you select appropriate permissions as well.', 'keyring' ), 'https://developers.nest.com/products/new', Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've set that up, copy your <strong>Product ID</strong> value into the <strong>API Key</strong> field, and the <strong>Product Secret</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Nest).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			if ( ! empty( $response->structures ) ) {
				$label = array();
				foreach ( $response->structures as $id => $structure ) {
					$label[] = $structure->name;
				}
				$meta = array(
					'name' => implode( ' / ', $label ),
				);
			}
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Nest', 'init' ) );
