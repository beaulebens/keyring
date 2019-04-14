<?php

/**
 * Google (Analytics) service definition for Keyring.
 *
 * Analytics Reporting API: https://developers.google.com/analytics/devguides/reporting/core/v4/
 * OAuth implementation: https://developers.google.com/identity/protocols/OAuth2WebServer
 * App registration: https://console.developers.google.com/
 */

class Keyring_Service_GoogleAnalytics extends Keyring_Service_GoogleBase {
	const NAME        = 'google-analytics';
	const LABEL       = 'Google Analytics';
	const SCOPE       = 'https://www.googleapis.com/auth/analytics.readonly https://www.googleapis.com/auth/userinfo.profile'; // See https://developers.google.com/identity/protocols/googlescopes
	const ACCESS_TYPE = 'offline';

	function __construct() {
		parent::__construct();
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__GOOGLEANALYTICS_KEY' )
		&&
			defined( 'KEYRING__GOOGLEANALYTICS_SECRET' )
		) {
			return array(
				'redirect_uri' => defined( 'KEYRING__GOOGLEANALYTICS_URI' ) ? constant( 'KEYRING__GOOGLEANALYTICS_URI' ) : '', // optional
				'key'          => constant( 'KEYRING__GOOGLEANALYTICS_KEY' ),
				'secret'       => constant( 'KEYRING__GOOGLEANALYTICS_SECRET' ),
			);
		} else {
			return null;
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_GoogleAnalytics', 'init' ) );
