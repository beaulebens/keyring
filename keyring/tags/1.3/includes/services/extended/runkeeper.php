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
		if ( ! KEYRING__HEADLESS_MODE )
			add_action( 'keyring_runkeeper_manage_ui', array( $this, 'basic_ui' ) );

		$this->set_endpoint( 'authorize',    'https://runkeeper.com/apps/authorize',    'GET'  );
		$this->set_endpoint( 'access_token', 'https://runkeeper.com/apps/token',        'POST' );
		$this->set_endpoint( 'deauthorize',  'https://runkeeper.com/apps/de-authorize', 'POST' );
		$this->set_endpoint( 'user',         'https://api.runkeeper.com/user',          'GET'  );
		$this->set_endpoint( 'profile',      'https://api.runkeeper.com/profile',       'GET'  );

		if (
			defined( 'KEYRING__RUNKEEPER_ID' )
		&&
			defined( 'KEYRING__RUNKEEPER_KEY' )
		&&
			defined( 'KEYRING__RUNKEEPER_SECRET' )
		) {
			$this->app_id  = KEYRING__RUNKEEPER_ID;
			$this->key     = KEYRING__RUNKEEPER_KEY;
			$this->secret  = KEYRING__RUNKEEPER_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->app_id  = $creds['app_id'];
			$this->key     = $creds['key'];
			$this->secret  = $creds['secret'];
		}

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
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
