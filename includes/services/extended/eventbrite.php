<?php

/**
 * Eventbrite service definition for Keyring.
 * http://developer.eventbrite.com/
 */

class Keyring_Service_Eventbrite extends Keyring_Service_OAuth2 {
	const NAME = 'eventbrite';
	const LABEL = 'Eventbrite';
	const API_BASE = 'https://www.eventbriteapi.com/v3/';
	const OAUTH_BASE = 'https://www.eventbrite.com/oauth/';

	function __construct() {
		parent::__construct();

		add_filter( 'keyring_' . $this->get_name() . '_request_token_params', array( $this, 'add_connection_referrer' ) );

		$this->set_endpoint( 'authorize', self::OAUTH_BASE . 'authorize', 'GET' );
		$this->set_endpoint( 'access_token', self::OAUTH_BASE . 'token', 'POST' );
		$this->set_endpoint( 'self', self::API_BASE . 'users/me/', 'GET' );

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_eventbrite_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_eventbrite_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
	}

	/**
	 * Append a referrer to the oAuth request made to Eventbrite, at their request
	 *
	 * See http://themedevp2.wordpress.com/2013/12/05/can-we-add-refwpoauth-to/
	 *
	 * @param array $params
	 * @filter keyring_eventbrite_request_token_params
	 * @return array
	 */
	public function add_connection_referrer( $params ) {
		if ( ! isset( $params['ref'] ) ) {
			$params['ref'] = 'wpoauth';
		}

		return $params;
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( "To get started, <a href='https://www.eventbrite.com/api/key'>register an OAuth client on Eventbrite</a>. The most important setting is the <strong>OAuth redirect_uri</strong>, which should be set to <code>%s</code>. You can set the other values to whatever you like.", 'keyring' ), esc_url(  Keyring_Util::admin_url( 'eventbrite', array( 'action' => 'verify' ) ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>APPLICATION KEY</strong> value into the <strong>API Key</strong> field, then click the 'Show' link next to the <strong>OAuth client secret</strong>, copy the value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Eventbrite).", 'keyring' ) . '</p>';
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
		$meta = array();
		if ( !Keyring_Util::is_error( $response ) ) {
			if ( isset( $response->emails->email ) ) {
				$meta['username'] = $response->emails->email;
			}

			if ( isset( $response->id ) ) {
				$meta['user_id'] = $response->id;
			}

			if ( isset( $response->name ) ) {
				$meta['name'] = $response->name;
			}
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'eventbrite', $token, null, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function test_connection() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( !Keyring_Util::is_error( $res ) ) {
			return true;
		}

		return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Eventbrite', 'init' ) );
