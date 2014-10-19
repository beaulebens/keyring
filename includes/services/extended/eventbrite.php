<?php

/**
 * Eventbrite service definition for Keyring.
 * https://developer.eventbrite.com/docs/
 */

class Keyring_Service_Eventbrite extends Keyring_Service_OAuth2 {
	const NAME = 'eventbrite';
	const LABEL = 'Eventbrite';
	const API_BASE = 'https://www.eventbriteapi.com/v3/';
	const OAUTH_BASE = 'https://www.eventbrite.com/oauth/';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( !KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_eventbrite_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_eventbrite_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$creds        = $this->get_credentials();
		$this->key    = $creds['key'];
		$this->secret = $creds['secret'];

		$this->consumer         = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer'; // Oh, you
		$this->authorization_parameter = false;

		$this->set_endpoint( 'authorize', self::OAUTH_BASE . 'authorize', 'GET' );
		$this->set_endpoint( 'access_token', self::OAUTH_BASE . 'token', 'POST' );
		$this->set_endpoint( 'self', self::API_BASE . 'users/me/', 'GET' );
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an OAuth client on Evenbrite</a>. The most important setting is the <strong>OAuth Redirect URI</strong>, which should be set to <code>%2$s</code>. You can set the other values to whatever you like.', 'keyring' ), 'https://www.eventbrite.com/myaccount/apps/', Keyring_Util::admin_url( 'eventbrite', array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>CLIENT/APPLICATION KEY</strong> value into the <strong>API Key</strong> field, and the <strong>CLIENT SECRET</strong> value into the <strong>API Secret</strong> field and click save.", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$meta = array();

		if ( empty( $token['access_token'] ) ) {
			return $meta;
		}

		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);

		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( !Keyring_Util::is_error( $response ) ) {
			$meta = array(
				'user_id' => $response->id,
				'name'    => $response->name,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'eventbrite', $token, $response, $this );
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
