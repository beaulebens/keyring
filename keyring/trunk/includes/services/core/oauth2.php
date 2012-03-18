<?php

class Keyring_Service_OAuth2 extends Keyring_Service_OAuth1 {
	function request_token() {
		$url = $this->authorize_url;
		if ( !stristr( $url, '?' ) )
			$url .= '?';
		$params = array(
			'response_type' => 'code',
			'client_id' => $this->key,
			'redirect_uri' => $this->callback_url,
		);
		Keyring_Util::debug( 'OAuth2 Redirect URL: ' . $url . http_build_query( $params ) );
		wp_redirect( $url . http_build_query( $params ) );
		exit;
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
				$this->store_token( $token->access_token, array() );
				wp_redirect( Keyring_Util::admin_url() );
			}
		}
		Keyring::error(
			sprintf( __( 'There was a problem authorizing with %s. Please try again in a moment.', 'keyring' ), $this->get_label() )
		);
		return false;
	}
	
	function request( $token, $url, $params = array() ) {
		if ( empty( $token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );
		
		$params = array_merge( array( 'oauth_token' => (string) $token ), $params );
		if ( empty( $params['oauth_token'] ) )
			return false;
		
		if ( stristr( $url, '?' ) )
			$url .= '&';
		else
			$url .= '?';
		$url .= 'oauth_token=' . $params['oauth_token'];
		unset( $params['oauth_token'] );
		
		$res = wp_remote_get( $url, $params );
		if ( 200 == wp_remote_retrieve_response_code( $res ) )
			return wp_remote_retrieve_body( $res );
		else
			return new Keyring_Error( 'keyring-request-error', $res );
	}
}
