<?php

/**
 * Google Mail (Gmail) service definition for Keyring.
 *
 * Gmail API: https://developers.google.com/gmail/api/v1/reference/
 * OAuth implementation: https://developers.google.com/identity/protocols/OAuth2WebServer
 * App registration: https://console.developers.google.com/
 */

class Keyring_Service_GoogleMail extends Keyring_Service_GoogleBase {
	const NAME        = 'google-mail';
	const LABEL       = 'Google Mail';
	const SCOPE       = 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.profile'; // See https://developers.google.com/identity/protocols/googlescopes
	const ACCESS_TYPE = 'offline';

	function __construct() {
		parent::__construct();
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__GOOGLEMAIL_KEY' )
		&&
			defined( 'KEYRING__GOOGLEMAIL_SECRET' )
		) {
			return array(
				'redirect_uri' => defined( 'KEYRING__GOOGLEMAIL_URI' ) ? constant( 'KEYRING__GOOGLEMAIL_URI' ) : '', // optional
				'key'          => constant( 'KEYRING__GOOGLEMAIL_KEY' ),
				'secret'       => constant( 'KEYRING__GOOGLEMAIL_SECRET' ),
			);
		} else {
			return null;
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_GoogleMail', 'init' ) );
