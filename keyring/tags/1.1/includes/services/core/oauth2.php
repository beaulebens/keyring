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

	/**
	 * If you're not sending the authorization in the header, some services will accept
	 * it as a querystring parameter. The spec says to send it as oauth_token, but some services
	 * want it called something else... like 'access_token'
	 * @var string
	 */
	var $authorization_parameter = 'oauth_token';

	function request_token() {
		$url = $this->authorize_url;
		if ( !stristr( $url, '?' ) )
			$url .= '?';
		$params = array(
			'response_type' => 'code',
			'client_id'     => $this->key,
			'redirect_uri'  => $this->callback_url,
		);
		$params = apply_filters( 'keyring_' . $this->get_name() . '_request_token_params', $params );
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
			'client_id'     => $this->key,
			'client_secret' => $this->secret,
			'grant_type'    => 'authorization_code',
			'redirect_uri'  => $this->callback_url,
			'code'          => $_GET['code'],
		);
		$params = apply_filters( 'keyring_' . $this->get_name() . '_verify_token_params', $params );
		Keyring_Util::debug( 'OAuth2 Access Token URL: ' . $url . http_build_query( $params ) );
		switch ( strtoupper( $this->access_token_method ) ) {
		case 'GET':
			$res = wp_remote_get( $url . http_build_query( $params ) );
			break;
		case 'POST':
			$res = wp_remote_post( $url, array( 'body' => $params ) );
			break;
		}

		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			$token = wp_remote_retrieve_body( $res );
			Keyring_Util::debug( $token );

			$token = $this->parse_access_token( $token );

			if ( is_array( $token ) ) {
				if ( method_exists( $this, 'custom_verify_token' ) )
					$this->custom_verify_token( $token );

				$meta = $this->build_token_meta( $token );

				$id = $this->store_token( $token['access_token'], $meta );
				$this->verified( $id );
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
		Keyring_Util::debug( $url );

		if ( $this->requires_token() && empty( $this->token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );

		$token = $this->token ? $this->token : null;

		if ( !is_null( $token ) ) {
			if ( $this->authorization_header ) {
				// type can be OAuth, Bearer, ...
				$params['headers']['Authorization'] = $this->authorization_header . ' ' . (string) $token;
			} else {
				$url = add_query_arg( array( $this->authorization_parameter => urlencode( (string) $token ) ), $url );
			}
		}

		$raw_response = false;
		if ( isset( $params['raw_response'] ) ) {
			$raw_response = (bool) $params['raw_response'];
			unset( $params['raw_response'] );
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

		Keyring_Util::debug( 'OAuth2 Params' );
		Keyring_Util::debug( $params );

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

		Keyring_Util::debug( 'OAuth2 Response' );
		Keyring_Util::debug( $res );

		if ( 200 == wp_remote_retrieve_response_code( $res ) || 201 == wp_remote_retrieve_response_code( $res ) )
			if ( $raw_response )
				return wp_remote_retrieve_body( $res );
			else
				return $this->parse_response( wp_remote_retrieve_body( $res ) );
		else
			return new Keyring_Error( 'keyring-request-error', $res );
	}

	/**
	 * OAuth2 implementations generally use JSON. You can still override this
	 * per service if you like, but by default we'll assume JSON.
	 */
	function parse_response( $response ) {
		return json_decode( $response );
	}
}
