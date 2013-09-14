<?php

/**
 * Tumblr service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Tumblr extends Keyring_Service_OAuth1 {
	const NAME  = 'tumblr';
	const LABEL = 'Tumblr';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_tumblr_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_tumblr_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'request_token', 'http://www.tumblr.com/oauth/request_token', 'POST' );
		$this->set_endpoint( 'authorize',     'http://www.tumblr.com/oauth/authorize',     'GET' );
		$this->set_endpoint( 'access_token',  'http://www.tumblr.com/oauth/access_token',  'POST' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header = true; // Send OAuth token in the header, not querystring
		$this->authorization_realm = 'tumblr.com';
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( "To get started, <a href='http://www.tumblr.com/oauth/register'>register an application with Tumblr</a>. The <strong>Default callback URL</strong> should be set to <code>%s</code>, and you can enter whatever you like in the other fields.", 'keyring' ), Keyring_Util::admin_url( 'tumblr', array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've created your app, copy the <strong>OAuth Consumer Key</strong> into the <strong>API Key</strong> field below. Click the <strong>Show secret key</strong> link, and then copy the <strong>Secret Key</strong> value into the <strong>API Secret</strong> field below. You don't need an App ID value for Tumblr.", 'keyring' ) . '</p>';
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				'tumblr',
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( 'http://api.tumblr.com/v2/user/info', array( 'method' => 'POST' ) );

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$this->person = $response->response->user;
			$meta = array(
				'name' => $this->person->name,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'tumblr', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
			$res = $this->request( 'http://api.tumblr.com/v2/user/info', array( 'method' => 'POST' ) );
			if ( !Keyring_Util::is_error( $res ) )
				return true;

			return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Tumblr', 'init' ) );
