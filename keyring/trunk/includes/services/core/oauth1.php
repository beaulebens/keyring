<?php

/**
 * Spec OAuth1 implementation for services using OAuth for authentication.
 * You will want to define request, access and authorize endpoints. Keyring
 * will walk the user through the OAuth dance. Once an access token is 
 * obtained, it's considered verified. You may still want to do an additional
 * request to get some details or verify something specific. To do that, hook
 * something to 'keyring_SERVICE_post_verification' (see Keyring_Service::verified())
 *
 * @package Keyring
 */
class Keyring_Service_OAuth1 extends Keyring_Service {
	var $request_token_url    = ''; // @see ::set_endpoint()
	var $request_token_method = 'GET';
	var $access_token_url     = '';
	var $access_token_method  = 'GET';
	var $authorize_url        = '';
	var $authorize_method     = 'GET';
	
	var $key                  = null;
	var $secret               = null;
	var $consumer             = null;
	var $signature_method     = null;
	var $callback_url         = null;
	
	var $token                = null;
	
	function __construct( $token = false ) {
		parent::__construct( $token );
		
		$class = get_called_class();
		$this->callback_url = Keyring_Util::admin_url( $class::NAME, array( 'action' => 'verify' ) );
		
		if ( !class_exists( 'OAuthRequest' ) )
			require dirname( dirname( dirname( __FILE__ ) ) ) . '/oauth-php/OAuth.php';
	}
	
	function get_display( $token ) {
		return $this->key;
	}
	
	function request_token() {
		$request_token_url = $this->request_token_url;
		if ( $this->callback_url ) {
			if ( strstr( $request_token_url, '?' ) )
				$request_token_url .= '&';
			else
				$request_token_url .= '?';
			$request_token_url .= 'oauth_callback=' . urlencode( $this->callback_url );
		}
		
		$query = '';
		$parsed = parse_url( $request_token_url );
		if ( !empty( $parsed['query'] ) && 'POST' == strtoupper( $this->request_token_method ) ) {
			$request_token_url = str_replace( $parsed['query'], '', $request_token_url );
			$query = $parsed['query'];
		}
		
		// Set up OAuth request
		$req = OAuthRequest::from_consumer_and_token(
			$this->consumer,
			null,
			$this->request_token_method,
			$request_token_url,
			null
		);
		$req->sign_request(
			$this->signature_method,
			$this->consumer,
			null
		);
		
		// Get a request token
		switch ( strtoupper( $this->request_token_method ) ) {
		case 'GET':
			Keyring_Util::debug( "OAuth GET Request Token URL: $req" );
			$res = wp_remote_get( $req );
			break;
			
		case 'POST':
			Keyring_Util::debug( "OAuth POST Request Token URL: $req" );
			$res = wp_remote_post( $req, array( 'body' => $query, 'sslverify' => false ) );
			break;
			
		default:
			wp_die( __( 'Unsupported method specified for request_token.', 'keyring' ) );
			exit;
		}
		
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			// Get the values returned from the remote service
			$token = wp_remote_retrieve_body( $res );
			parse_str( trim( $token ), $token );
			
			// Set some values to the current domain so that we can retrieve them later
			$host = parse_url( site_url(), PHP_URL_HOST );
			$host = str_replace( 'www.', '', $host );
			
			// The token secret is important
			setcookie( "keyring_{$this->get_name()}", $token['oauth_token_secret'], ( time() + 60 * 60 ), '/', ".$host" );
			
			// Sometimes we have a verifier which we can use to confirm things later
			if ( isset( $token['oauth_verifier'] ) )
				setcookie( "keyring_{$this->get_name()}_verifier", $token['oauth_verifier'], ( time() + 60 * 60 ), '/', ".$host" );
		} else {
			Keyring::error(
				sprintf( __( 'There was a problem connecting to %s to create an authorized connection. Please try again in a moment.', 'keyring' ), $this->get_label() )
			);
			return false;
		}
		
		// Redirect user to get us an authorize token
		$authorize = $this->authorize_url . '?oauth_token=' . urlencode( $token['oauth_token'] );
		if ( $this->callback_url )
			$authorize .= '&oauth_callback=' . urlencode( $this->callback_url );
		
		Keyring_Util::debug( "OAuth Authorize Redirect: $authorize", KEYRING__DEBUG_NOTICE );
		wp_redirect( $authorize );
		exit;
	}
	
	function verify_token() {
		Keyring_Util::debug( 'Keyring_Service_OAuth1::verify_token()' );
		// Get an access token
		$token = isset( $_GET['oauth_token'] ) ? $_GET['oauth_token'] : false;
		if ( empty( $token ) && isset( $_GET['?oauth_token'] ) )
		    $token = $_GET['?oauth_token'];

		$secret = $_COOKIE["keyring_{$this->get_name()}"];

		$access_token_url = $this->access_token_url;
		if ( !empty( $_GET['oauth_verifier'] ) ) {
			if ( stristr( $access_token_url, '?' ) )
				$access_token_url .= '&';
			else
				$access_token_url .= '?';
			$access_token_url .= 'oauth_verifier=' . $_GET['oauth_verifier'];
		}
		
		// Set up a consumer token
		$token = new OAuthConsumer( $token, $secret );
		Keyring_Util::debug( 'OAuthConsumer: ' . print_r( $token, true ) );
		
		$query = '';
		$parsed = parse_url( $access_token_url );
		if ( !empty( $parsed['query'] ) && 'POST' == strtoupper( $this->access_token_method ) ) {
			$access_token_url = str_replace( $parsed['query'], '', $access_token_url );
			$query = $parsed['query'];
		}
		
		// Set up OAuth request
		$req = OAuthRequest::from_consumer_and_token(
			$this->consumer,
			$token,
			$this->access_token_method,
			$access_token_url
		);
		$req->sign_request(
			$this->signature_method,
			$this->consumer,
			$token
		);
		
		// Make verification request
		switch ( strtoupper( $this->access_token_method ) ) {
		case 'GET':
			Keyring_Util::debug( "OAuth GET Verify Token URL: $req" );
			$res = wp_remote_get( $req );
			break;
			
		case 'POST':
			Keyring_Util::debug( "OAuth POST Verify Token URL: $req" );
			$res = wp_remote_post( $req, array( 'body' => $query, 'sslverify' => false ) );
			break;
			
		default:
			wp_die( __( 'Unsupported method specified for verify_token.', 'keyring' ) );
			exit;
		}
		
		Keyring_Util::debug( $res );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			$token = wp_remote_retrieve_body( $res );
			parse_str( trim( $token ), $token );
			
			if ( method_exists( $this, 'custom_verify_token' ) )
				$this->custom_verify_token( $token );
			
			$meta = array();
			if ( method_exists( $this, 'build_token_meta' ) )
				$meta = $this->build_token_meta( $token );
			
			$id = $this->store_token( $token['oauth_token'], $meta );
			$this->verified( $id );
		} else {
			Keyring::error(
				sprintf( __( 'There was a problem connecting to %s to create an authorized connection. Please try again in a moment.', 'keyring' ), $this->get_label() )
			);
			return false;
		}
	}
	
	function request( $url, $params = array() ) {
		if ( $this->requires_token() && empty( $this->token ) )
			return new Keyring_Error( 'keyring-request-error', __( 'No token' ) );
		
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
		
		$token = $this->token->token ? $this->token->token : null;
		
		$req = OAuthRequest::from_consumer_and_token(
			$this->consumer,
			$token,
			$method,
			$url,
			$params
		);
		$req->sign_request(
			$this->signature_method,
			$this->consumer,
			$token
		);
		
		Keyring_Util::debug( "OAuth1 Request URL: $req" );
		switch ( $method ) {
		case 'GET':
			$res = wp_remote_get( (string) $req, $params );
			break;
			
		case 'POST':
			// TODO support POST (test post-body etc)
			$params = array_merge( array( 'body' => $query, 'sslverify' => false ), $params );
			$res = wp_remote_post( (string) $req, $params );
			break;
			
		default:
			wp_die( __( 'Unsupported method specified.', 'keyring' ) );
			exit;
		}
		
		Keyring_Util::debug( $res );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			return wp_remote_retrieve_body( $res );
		} else {
			return new Keyring_Error( 'keyring-request-error', $res );
		}
	}
}
