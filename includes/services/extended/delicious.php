<?php

class Keyring_Service_Delicious extends Keyring_Service_HTTP_Basic {
	const NAME  = 'delicious';
	const LABEL = 'delicious.com';

	function __construct() {
		parent::__construct();
		$this->set_endpoint( 'verify', 'https://api.del.icio.us/v1/posts/update', 'GET' );
		$this->requires_token( true );
	}

	function _get_credentials() {
		return false;
	}

	function parse_response( $data ) {
		return simplexml_load_string( $data );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'username' );
	}

	function test_connection() {
		$response = $this->request( 'https://api.del.icio.us/v1/posts/all?results=1' );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Delicious', 'init' ) );
