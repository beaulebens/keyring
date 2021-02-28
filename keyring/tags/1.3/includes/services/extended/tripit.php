<?php

/**
 * TripIt service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_TripIt extends Keyring_Service_OAuth1 {
	const NAME  = 'tripit';
	const LABEL = 'TripIt';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE )
			add_action( 'keyring_tripit_manage_ui', array( $this, 'basic_ui' ) );

		$this->authorization_header = true;
		$this->authorization_realm  = false;

		$this->set_endpoint( 'request_token', 'https://api.tripit.com/oauth/request_token',  'POST' );
		$this->set_endpoint( 'authorize',     'https://www.tripit.com/oauth/authorize',      'GET'  );
		$this->set_endpoint( 'access_token',  'https://api.tripit.com/oauth/access_token',   'POST' );
		$this->set_endpoint( 'verify',        'https://api.tripit.com/v1/get/profile/id/me', 'GET'  );

		if (
			defined( 'KEYRING__TRIPIT_ID' )
		&&
			defined( 'KEYRING__TRIPIT_KEY' )
		&&
			defined( 'KEYRING__TRIPIT_SECRET' )
		) {
			$this->app_id  = KEYRING__TRIPIT_ID;
			$this->key     = KEYRING__TRIPIT_KEY;
			$this->secret  = KEYRING__TRIPIT_SECRET;
		} else if ( $creds = $this->get_credentials() ) {
			$this->app_id  = $creds['app_id'];
			$this->key     = $creds['key'];
			$this->secret  = $creds['secret'];
		}

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'    => $response->Profile->{'@attributes'}->ref,
				'username'   => $response->Profile->screen_name,
				'name'       => $response->Profile->public_display_name,
				'picture'    => $response->Profile->photo_url,
				'_classname' => get_called_class(),
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'tripit', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function request( $url, array $params = array() ) {
		$url = add_query_arg( array( 'format' => 'json' ), $url );
		return parent::request( $url, $params );
	}

	function test_connection() {
		$response = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		if ( !Keyring_Util::is_error( $response ) )
			return true;

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_TripIt', 'init' ) );
