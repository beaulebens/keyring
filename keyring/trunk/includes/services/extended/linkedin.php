<?php

return;

/**
 * LinkedIn service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_LinkedIn extends Keyring_Service_OAuth1 {
	const NAME  = 'linkedin';
	const LABEL = 'LinkedIn';

	function __construct( $token = false ) {
		parent::__construct( $token );
		$this->set_endpoint( 'request_token', 'https://api.linkedin.com/uas/oauth/requestToken', 'POST' );
		$this->set_endpoint( 'authorize',     'https://api.linkedin.com/uas/oauth/authorize',    'GET'  );
		$this->set_endpoint( 'access_token',  'https://api.linkedin.com/uas/oauth/accessToken',  'GET'  );
		
		$this->app_id = KEYRING__LINKEDIN_ID;
		$this->key = KEYRING__LINKEDIN_KEY;
		$this->secret = KEYRING__LINKEDIN_SECRET;
		
		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
	}
	
	function parse_response( $response ) {
		return json_decode( $response );
	}
	
	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Token(
				'linkedin',
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				),
				array(
					'type' => 'access',
				)
			)
		);
		
		// Get user profile information
		$response = $this->request( "https://api.linkedin.com/v1/people/~:(id,formatted-name)?format=json" );
		
		if ( Keyring_Util::is_error( $response ) )
			return array();
		
		$this->person = $response;
		$meta = array(
			'user_id' => $this->person->id,
			'name'    => $this->person->formattedName,
		);
		
		return $meta;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_LinkedIn', 'init' ) );
