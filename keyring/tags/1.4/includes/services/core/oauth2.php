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
		Keyring_Util::debug( 'Keyring_Service_OAuth2::request_token()' );
		if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-request-' . $this->get_name() ) ) {
			Keyring::error( __( 'Invalid/missing request nonce.', 'keyring' ) );
			exit;
		}

		// Need to create a request token now, so that we have a state to pass
		$request_token = new Keyring_Request_Token(
			$this->get_name(),
			array(),
			apply_filters(
				'keyring_request_token_meta',
				array(
					'for' => isset( $_REQUEST['for'] ) ? (string) $_REQUEST['for'] : false
				),
				$this->get_name(),
				array(), // no token
				$this
			)
		);
		$request_token     = apply_filters( 'keyring_request_token', $request_token, $this );
		$request_token_id  = $this->store_token( $request_token );

		$url = $this->authorize_url;
		if ( !stristr( $url, '?' ) )
			$url .= '?';
		$params = array(
			'response_type' => 'code',
			'client_id'     => $this->key,
			'redirect_uri'  => $this->callback_url,
			'state'         => $request_token_id,
		);
		$params = apply_filters( 'keyring_' . $this->get_name() . '_request_token_params', $params );
		Keyring_Util::debug( 'OAuth2 Redirect URL: ' . $url . http_build_query( $params ) );

		wp_redirect( $url . http_build_query( $params ) );
		exit;
	}

	function verify_token() {
		Keyring_Util::debug( 'Keyring_Service_OAuth2::verify_token()' );
		if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-verify-' . $this->get_name() ) ) {
			Keyring::error( __( 'Invalid/missing verification nonce.', 'keyring' ) );
			exit;
		}

		if ( !isset( $_GET['code'] ) || !isset( $_GET['state']) ) {
			Keyring::error(
				sprintf( __( 'There was a problem authorizing with %s. Please try again in a moment.', 'keyring' ), $this->get_label() )
			);
			return false;
		}

		// Load up the request token that got us here and globalize it
		global $keyring_request_token;
		$state = (int) $_GET['state'];
		$keyring_request_token = $this->store->get_token( array( 'id' => $state, 'type' => 'request' ) );
		Keyring_Util::debug( 'OAuth2 Loaded Request Token ' . $_GET['state'] );
		Keyring_Util::debug( $keyring_request_token );

		if ( !$keyring_request_token ) {
			Keyring::error(
				sprintf( __( 'Failed to load your request token while connecting to %s. Please try again in a moment.', 'keyring' ), $this->get_label() )
			);
			return false;
		}

		$error_debug_info = array();

		if ( !empty( $keyring_request_token->meta['blog_id'] ) && !empty( $keyring_request_token->meta['user_id'] ) ) {
			$error_debug_info = array(
				'blog_id' => $keyring_request_token->meta['blog_id'],
				'user_id' => $keyring_request_token->meta['user_id']
			);
		}

		// Remove request token, don't need it any more.
		$this->store->delete( array( 'id' => $state, 'type' => 'request' ) );

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
		Keyring_Util::debug( 'OAuth2 Response' );
		Keyring_Util::debug( $res );

		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			$token = wp_remote_retrieve_body( $res );
			Keyring_Util::debug( $token );

			$token = $this->parse_access_token( $token );

			$access_token = new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				$this->build_token_meta( $token )
			);
			$access_token = apply_filters( 'keyring_access_token', $access_token, $token );

			Keyring_Util::debug( 'OAuth2 Access Token for storage' );
			Keyring_Util::debug( $access_token );
			$id = $this->store_token( $access_token );
			$this->verified( $id, $keyring_request_token );
			exit;
		}
		Keyring::error(
			sprintf( __( 'There was a problem authorizing with %s. Please try again in a moment.', 'keyring' ), $this->get_label() ),
			$error_debug_info
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
			Keyring::error( __( 'Unsupported method specified for request_token.', 'keyring' ) );
			exit;
		}

		Keyring_Util::debug( 'OAuth2 Response' );
		Keyring_Util::debug( $res );

		$this->set_request_response_code( wp_remote_retrieve_response_code( $res ) );
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
