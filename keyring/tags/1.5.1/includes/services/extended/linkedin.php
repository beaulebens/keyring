<?php

/**
 * LinkedIn service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_LinkedIn extends Keyring_Service_OAuth1 {
	const NAME  = 'linkedin';
	const LABEL = 'LinkedIn';

	function __construct() {
		parent::__construct();

		$this->authorization_header = true;
		$this->authorization_realm = "api.linkedin.com";

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_linkedin_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_linkedin_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'request_token', 'https://api.linkedin.com/uas/oauth/requestToken', 'POST' );
		$this->set_endpoint( 'authorize',     'https://api.linkedin.com/uas/oauth/authorize',    'GET'  );
		$this->set_endpoint( 'access_token',  'https://api.linkedin.com/uas/oauth/accessToken',  'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
	}

	function basic_ui_intro() {
		echo '<p>' . __( "To connect to LinkedIn, you'll first need to <a href='https://www.linkedin.com/secure/developer?newapp='>create an app</a>. A lot of the details are required, but they're not actually important to the operation of your app, since Keyring will override any important settings.", 'keyring' ) . '</p>';
		echo '<p>' . __( "Once you've created your app, go down to the <strong>OAuth Keys</strong> section and copy the <strong>API Key</strong> value into the <strong>API Key</strong> field below, and the <strong>Secret Key</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for LinkedIn).", 'keyring' ) . '</p>';
	}

	function parse_response( $response ) {
		if ( '<?xml' == substr( $response, 0, 5 ) ) // Errors always come back as XML
			return simplexml_load_string( $response );
		else
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

		// Get user profile information
		$response = $this->request( "https://api.linkedin.com/v1/people/~:(id,formatted-name,picture-url)?format=json" );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$this->person = $response;
			$meta = array(
				'user_id' => $this->person->id,
				'name'    => $this->person->formattedName,
				'picture' => $this->person->pictureUrl,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta,  'linkedin', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
			$res = $this->request( "https://api.linkedin.com/v1/people/~:(id,formatted-name)?format=json" );
			if ( !Keyring_Util::is_error( $res ) )
				return true;

			return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_LinkedIn', 'init' ) );
