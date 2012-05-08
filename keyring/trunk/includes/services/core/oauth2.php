<?php

/**
 * Spec OAuth2 implementation for services using OAuth for authentication.
 * You will want to define an authorize and access_token endpoint. Keyring
 * will walk the user through the OAuth dance. Once an access token is 
 * obtained, it's considered verified. You may still want to do an additional
 * request to get some details or verify something specific. To do that, hook
 * something to 'keyring_SERVICE_post_verification' (see Keyring_Service::verified())
 *
 * @package Keyring
 */
class Keyring_Service_OAuth2 extends Keyring_Service_OAuth1 {
	/**
	 * Tokens should be passed in the authorization header if the service supports it
	 * and only fallback to the query string if neccessary. Set to false to use ?oauth_token=
	 */
	var $authorization_header = 'OAuth';
	
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
			
			$token = $this->parse_access_token( $token );
			
			if ( is_array( $token ) ) {
				if ( method_exists( $this, 'custom_verify_token' ) )
					$this->custom_verify_token( $token );

				$meta = $this->build_token_meta( $token );
				
				$this->store_token( $token['access_token'], $meta );
				wp_redirect( Keyring_Util::admin_url() );
				exit;
			}
		}
		Keyring::error(
			sprintf( __( 'There was a problem authorizing with %s. Please try again in a moment.', 'keyring' ), $this->get_label() )
		);
		return false;
	}
	
	/**
	 * The OAuth2 spec indicates that responses should be in JSON, but separating
	 * this allows different services to potentially use querystring-encoded
	 * responses or something else, and just define this method within themselves
	 * to handle decoding the access_token response.
	 *
	 * @param string $token The response from the access_token request
	 * @return Array containing key/value pairs from the token response
	 */
	function parse_access_token( $token ) {
		return (array) json_decode( $token );
	}
	
	function request( $url, array $params = array() ) {
		if ( $this->requires_token() && empty( $this->token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );
		
		if ( $this->token ) {
			if ( $this->authorization_header ) {
				// type can be OAuth, Bearer, ...
				$params['headers']['Authorization'] = $this->authorization_header . ' ' . (string) $this->token;
			} else {
				$url = add_query_arg( array( 'oauth_token' => urlencode( (string) $this->token ) ), $url );
			}
		}
		
		$method = 'GET';
		if ( isset( $params['method'] ) ) {
			$method = strtoupper( $params['method'] );
			unset( $params['method'] );
		}
		
		$query = '';
		$parsed = parse_url( $url );
		if ( !empty( $parsed['query'] ) && 'POST' == $method ) {
			$url = str_replace( $parsed['query'], '', $url );
			$query = $parsed['query'];
		}
		
		switch ( strtoupper( $method ) ) {
		case 'GET':
			$res = wp_remote_get( $url, $params );
			break;
			
		case 'POST':
			$params = array_merge( array( 'body' => $query, 'sslverify' => false ), $params );
			$res = wp_remote_post( $url, $params );
			break;
			
		default:
			wp_die( __( 'Unsupported method specified for request_token.', 'keyring' ) );
			exit;
		}
		
		if ( 200 == wp_remote_retrieve_response_code( $res ) )
			return wp_remote_retrieve_body( $res );
		else
			return new Keyring_Error( 'keyring-request-error', $res );
	}
}
