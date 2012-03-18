<?php

/**
 * Foursquare service definition for Keyring. Actually OAuth2, but can be done using the OAuth1 Service
 * https://developer.foursquare.com/docs/oauth.html
 * https://foursquare.com/oauth/
 */

class Keyring_Service_Foursquare extends Keyring_Service_OAuth2 {
	const NAME  = 'foursquare';
	const LABEL = 'Foursquare';
	
	var $self_url    = '';
	var $self_method = '';

	function __construct( $details = array() ) {
		parent::__construct( $details );
		
		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_foursquare_manage_ui', array( $this, 'basic_ui' ) );
		
		$this->set_endpoint( 'authorize',    'https://foursquare.com/oauth2/authenticate' );
		$this->set_endpoint( 'access_token', 'https://foursquare.com/oauth2/access_token' );
		$this->set_endpoint( 'self',         'https://api.foursquare.com/v2/users/self'   );
		
		if ( $creds = $this->get_credentials() ) {
			$this->key = $creds['key'];
			$this->secret = $creds['secret'];
		} else if ( defined( 'KEYRING__FOURSQUARE_KEY' ) && defined( 'KEYRING__FOURSQUARE_SECRET' ) ) {
			$this->key = KEYRING__FOURSQUARE_KEY;
			$this->secret = KEYRING__FOURSQUARE_SECRET;
		}
		
		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
	}
	
	function verify_token() {
		if ( !isset( $_GET['code'] ) ) {
			Keyring::error(
				sprintf( __( 'There was a problem authorizing with %s. Please try again in a moment.', 'keyring' ), $this->get_label() )
			);
			return false;
		}

		$url = $this->access_token_url;
		if ( !stristr( $url, '?' ) )
			$url .= '?';
		$params = array(
			'client_id' => $this->key,
			'client_secret' => $this->secret,
			'grant_type' => 'authorization_code',
			'redirect_uri' => $this->callback_url,
			'code' => $_GET['code'],
		);
		Keyring_Util::debug( 'OAuth2 Access Token URL: ' . $url . http_build_query( $params ) );
		$res = wp_remote_get( $url . http_build_query( $params ) );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			$token = wp_remote_retrieve_body( $res );
			Keyring_Util::debug( $token );
			if ( $token = json_decode( $token ) ) {
				$keyring_token = new Keyring_Token( $this->get_name(), $token->access_token, array() );
				$res = $this->request( $keyring_token, $this->self_url );
				if ( !Keyring_Util::is_error( $res ) ) {
					if ( $res = json_decode( $res ) ) {
						$meta = array(
							'id' => $res->response->user->id,
							'firstName' => $res->response->user->firstName,
							'lastName' => $res->response->user->lastName,
						);
						$id = $this->store_token( $token->access_token, $meta );
						$this->verified( $id );
					}
				} else {
					Keyring_Util::debug( $res );
				}
			}
		}
		Keyring::error(
			sprintf( __( 'There was a problem authorizing with %s. Please try again in a moment.', 'keyring' ), $this->get_label() )
		);
		return false;
	}
	
	function get_display( $token ) {
		$meta = $token->get_meta();
		return trim( $meta['firstName'] . ' ' . $meta['lastName'] ) . ' (' . $meta['id'] . ')';
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Foursquare', 'init' ) );
