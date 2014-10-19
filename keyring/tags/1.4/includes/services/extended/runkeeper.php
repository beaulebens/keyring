<?php

/**
 * Runkeeper service definition for Keyring.
 * http://developer.runkeeper.com/
 */

class Keyring_Service_RunKeeper extends Keyring_Service_OAuth2 {
	const NAME  = 'runkeeper';
	const LABEL = 'RunKeeper';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_runkeeper_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_runkeeper_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://runkeeper.com/apps/authorize',    'GET'  );
		$this->set_endpoint( 'access_token', 'https://runkeeper.com/apps/token',        'POST' );
		$this->set_endpoint( 'deauthorize',  'https://runkeeper.com/apps/de-authorize', 'POST' );
		$this->set_endpoint( 'user',         'https://api.runkeeper.com/user',          'GET'  );
		$this->set_endpoint( 'profile',      'https://api.runkeeper.com/profile',       'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
	}

	function basic_ui_intro() {
		echo '<p>' . __( "You'll need to <a href='http://runkeeper.com/partner/applications/registerForm'>register a new application</a> on RunKeeper so that you can connect. Be sure to check the <strong>Read Health Information</strong> option under <strong>Permissions Requests</strong> (and explain why you want to read that data). You will also be required to set an <strong>Estimated Date of Publication</strong>.", 'keyring' ) . '</p>';
		echo '<p>' . __( "Once you've registered your application, click the <strong>Application Keys and URLs</strong> next to it, and copy the <strong>Client ID</strong> into the <strong>API Key</strong> field below, and the <strong>Client Secret</strong> value into <strong>API Secret</strong>.", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			// Only useful thing in that request is userID
			$meta = array( 'user_id' => (int) $response->userID );

			// Now get the rest of their profile
			$profile = $this->request( $this->profile_url, array( 'profilethod' => $this->profile_method ) );
			if ( !Keyring_Util::is_error( $profile ) ) {
				$meta['username'] = substr( $profile->profile, strrpos( $profile->profile, '/' ) + 1 );
				$meta['name']     = $profile->name;
				$meta['picture']  = $profile->large_picture;
			}

			return apply_filters( 'keyring_access_token_meta', $meta, 'runkeeper', $token, $profile, $this );
		}
		return array();
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_RunKeeper', 'init' ) );
