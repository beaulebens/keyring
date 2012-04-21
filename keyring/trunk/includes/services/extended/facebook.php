<?php

/**
 * Facebook service definition for Keyring. Clean implementation of OAuth2
 */

class Keyring_Service_Facebook extends Keyring_Service {
	const NAME  = 'facebook';
	const LABEL = 'Facebook';

	function __construct() {
		parent::__construct();
		
		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_facebook_manage_ui', array( &$this, 'basic_ui' ) );
		
		if ( $creds = $this->get_credentials() ) {
			$this->app_id = $creds['key'];
			$this->secret = $creds['secret'];
		} else if ( defined( 'KEYRING__FACEBOOK_ID' ) && defined( 'KEYRING__FACEBOOK_SECRET' ) ) {
			$this->app_id = KEYRING__FACEBOOK_ID;
			$this->secret = KEYRING__FACEBOOK_SECRET;
		}
		
		$kr_nonce = wp_create_nonce( 'keyring-verify' );
		$nonce = wp_create_nonce( 'keyring-verify-facebook' );
		$this->redirect_uri = Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify', 'kr_nonce' => $kr_nonce, 'nonce' => $nonce, ) );
		
		$this->requires_token( true );
	}
	
	function request_token() {
		// Redirect to FB to handle logging in and authorizing
		$params = array(
			'client_id' => $this->app_id,
			'redirect_uri' => $this->redirect_uri,
			'scope' => implode( ',', apply_filters( 'keyring_facebook_scope', array( 'offline_access', 'publish_stream' ) ) ),
		);
		wp_redirect( 'https://www.facebook.com/dialog/oauth?' . http_build_query( $params ) );
		exit;
	}
	
	function get_display( Keyring_Token $token ) {
		$meta = $token->get_meta();
		return $meta['name'];
	}
	
	function verify_token() {
		// Something went wrong
		if ( empty( $_GET['code'] ) ) {
			Keyring::error( __( 'A valid <code>code</code> was not returned from Facebook. Please try again in a minute.' ) );
			return;
		}
		
		// Use code to get an access token
		$params = array(
			'client_id' => $this->app_id,
			'redirect_uri' => $this->redirect_uri,
			'client_secret' => $this->secret,
			'code' => $_GET['code'],
		);
		$res = wp_remote_get( "https://graph.facebook.com/oauth/access_token?" . http_build_query( $params ), array( 'sslverify' => false ) );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			$token = wp_remote_retrieve_body( $res );
			parse_str( trim( $token ), $token );
			
			$this->set_token( new Keyring_Token( 'facebook', $token['access_token'] ) );
			$res = $this->request( "https://graph.facebook.com/me" );
			if ( !Keyring_Util::is_error( $res ) ) {
				if ( empty( $res->username ) )
					$res->username = $res->name; // not all fb users have a set username
				
				$id = $this->store_token( $token['access_token'], array(
					'id' => $data->id,
					'username' => $data->username,
					'name' => $data->name,
					'link' => $data->link,
				) );
				
				$this->verified( $id );
				exit;
			} else {
				Keyring::error( __( 'Could not verify your Facebook profile information.' ) );
				return;
			}
		}
	}
	
	function request( $url, array $params = array() ) {
		if ( empty( $this->token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );
		
		// TODO prefer to send token in Authorization header when supported
		$url = add_query_arg( array( 'access_token' => urlencode( (string) $this->token ) ), $url );
		
		$res = wp_remote_get( $url, array( 'sslverify' => false ) );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			return json_decode( wp_remote_retrieve_body( $res ) );
		} else {
			return new Keyring_Error( 'keyring-request-error', $res );
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Facebook', 'init' ) );
