<?php

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
	
	function __construct( $details = array() ) {
		parent::__construct( $details );
		
		if ( !empty( $details['key'] ) )
			$this->key = $details['key'];
		if ( !empty( $details['secret'] ) )
			$this->secret = $details['secret'];
		
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
		
		// Get a request token
		if ( 'GET' == $this->request_token_method ) {
			// GET
			$req = OAuthRequest::from_consumer_and_token(
				$this->consumer,
				null,
				$this->request_token_method,
				$request_token_url,
				$params
			);
			$req->sign_request(
				$this->signature_method,
				$this->consumer,
				null
			);
			
			Keyring_Util::debug( "OAuth GET Request Token URL: $req" );
			$res = wp_remote_get( $req );
			if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
				$token = wp_remote_retrieve_body( $res );
				parse_str( trim( $token ), $token );
				$host = parse_url( site_url(), PHP_URL_HOST );
				$host = str_replace( 'www.', '', $host );
				setcookie( "keyring_{$this->get_name()}", $token['oauth_token_secret'], ( time() + 60 * 60 ), '/', ".$host" );
			} else {
				Keyring::error(
					sprintf( __( 'There was a problem connecting to %s to create an authorized connection. Please try again in a moment.', 'keyring' ), $this->get_label() )
				);
				return false;
			}
		} else {
			// POST
			
			// Parse out querystring to put in the body
			$parsed = parse_url( $this->request_token_url );
			
			$req = OAuthRequest::from_consumer_and_token(
				$this->consumer,
				null,
				$this->request_token_method,
				str_replace( $parsed['query'], '', $request_token_url ),
				$params
			);
			$req->sign_request(
				$this->signature_method,
				$this->consumer,
				null
			);
			
			Keyring_Util::debug( "OAuth POST Request Token URL: $req" );
			$res = wp_remote_post( $req, array( 'body' => $parsed['query'], 'sslverify' => false ) );
			Keyring_Util::debug( $parsed['query'] );
			Keyring_Util::debug( $res );
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
		$token = $_GET['oauth_token'];
		if ( empty( $token ) && isset( $_GET['?oauth_token'] ) )
		    $token = $_GET['?oauth_token'];

		$secret = $_COOKIE["keyring_{$this->get_name()}"];
		if ( !empty( $_GET['oauth_verifier'] ) ) {
			if ( stristr( $this->access_token_url, '?' ) )
				$this->access_token_url .= '&';
			else
				$this->access_token_url .= '?';
			$this->access_token_url .= 'oauth_verifier=' . $_GET['oauth_verifier'];
		}
		
		// Set up a consumer token
		Keyring_Util::debug( "Using oauth_token=$token" );
		$token = new OAuthConsumer( $token, $secret );
		Keyring_Util::debug( 'OAuthConsumer: ' . print_r( $token, true ) );
		
		// Make verification request
		if ( 'GET' == $this->access_token_method ) {
			// GET
			$req = OAuthRequest::from_consumer_and_token(
				$this->consumer,
				$token,
				$this->access_token_method,
				$this->access_token_url
			);
			$req->sign_request(
				$this->signature_method,
				$this->consumer,
				$token
			);
			
			Keyring_Util::debug( "OAuth GET Access Token URL: $req" );
			$res = wp_remote_get( $req );
			if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
				$token = wp_remote_retrieve_body( $res );
				parse_str( trim( $token ), $token );

				$id = $this->store_token( $token['oauth_token'], array(
					'secret' => $token['oauth_token_secret'],
					'user_id' => $token['user_nsid'],
					'username' => $token['username'],
					'full_name' => $token['fullname'],
				) );
				$this->verified( $id );
			} else {
				// @todo - throw error, bail
			}
		} else {
			// POST
			// Parse out querystring to put in the body
			$parsed = parse_url( $this->access_token_url );
			parse_str( $parsed['query'], $params );
			
			$req = OAuthRequest::from_consumer_and_token(
				$this->consumer,
				$token,
				$this->access_token_method,
				str_replace( $parsed['query'], '', $this->access_token_url ),
				$params
			);
			$req->sign_request(
				$this->signature_method,
				$this->consumer,
				$token
			);
			
			Keyring_Util::debug( "OAuth POST Access Token URL: $req" );
			$res = wp_remote_post( $req, array( 'body' => $parsed['query'], 'sslverify' => false ) );
			Keyring_Util::debug( $res );
			if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
				$token = wp_remote_retrieve_body( $res );
				parse_str( trim( $token ), $token );
				
				$id = $this->store_token( $token['oauth_token'], array(
					'secret' => $token['oauth_token_secret'],
					'user_id' => $token['user_id'],
					'screen_name' => $token['screen_name'],
				) );
				$this->verified( $id );
			} else {
				Keyring::error(
					sprintf( __( 'There was a problem connecting to %s to create an authorized connection. Please try again in a moment.', 'keyring' ), $this->get_label() )
				);
				return false;
			}
		}
	}
	
	function request( $token, $url, $params = array() ) {
		$method = strtoupper( $params['method'] );
		unset( $params['method'] );
		$req = OAuthRequest::from_consumer_and_token(
			$this->consumer,
			null,
			$method,
			$url,
			$params
		);
		$req->sign_request(
			$this->signature_method,
			$this->consumer,
			null
		);
		
		Keyring_Util::debug( "OAuth1 Request URL: $req" );
		Keyring_Util::debug( $req );
		$res = wp_remote_get( $req, $params );
		Keyring_Util::debug( $res );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			return wp_remote_retrieve_body( $res );
		} else {
			return new Keyring_Error( 'keyring-request-error', $res );
		}
	}
}
