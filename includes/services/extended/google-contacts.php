<?php

/**
 * Google (Contacts) service definition for Keyring.
 *
 * Contacts API: https://developers.google.com/google-apps/contacts/v3/
 * OAuth implementation: https://developers.google.com/accounts/docs/OAuth2WebServer
 * App registration: https://code.google.com/apis/console/
 */

class Keyring_Service_GoogleContacts extends Keyring_Service_GoogleBase {
	const NAME        = 'google-contacts';
	const LABEL       = 'Google Contacts';
	const SCOPE       = 'https://www.google.com/m8/feeds https://www.googleapis.com/auth/userinfo.profile'; // See https://developers.google.com/google-apps/contacts/v3/#authorizing_requests_with_oauth_20
	const API_VERSION = '3.0';
	const ACCESS_TYPE = 'offline';

	function __construct() {
		parent::__construct();
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__GOOGLECONTACTS_KEY' )
		&&
			defined( 'KEYRING__GOOGLECONTACTS_SECRET' )
		) {
			return array(
				'redirect_uri' => defined( 'KEYRING__GOOGLECONTACTS_URI' ) ? constant( 'KEYRING__GOOGLECONTACTS_URI' ) : '', // optional
				'key'          => constant( 'KEYRING__GOOGLECONTACTS_KEY' ),
				'secret'       => constant( 'KEYRING__GOOGLECONTACTS_SECRET' ),
			);
		} else {
			return null;
		}
	}

	function request( $url, array $params = array() ) {
		// add header (version), required for all requests
		$params['headers']['GData-Version'] = self::API_VERSION;
		return parent::request( $url, $params );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_GoogleContacts', 'init' ) );
