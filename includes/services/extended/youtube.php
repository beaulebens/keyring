<?php

/**
 * YouTube Service for Keyring.
 *
 * YouTube API: https://developers.google.com/youtube/v3/sample_requests
 * OAuth implementation: https://developers.google.com/youtube/v3/guides/auth/server-side-web-apps
 * App registration: https://console.developers.google.com/
 */

class Keyring_Service_YouTube extends Keyring_Service_GoogleBase {
	const NAME        = 'youtube';
	const LABEL       = 'YouTube';
	const SCOPE       = 'https://www.googleapis.com/auth/youtube https://www.googleapis.com/auth/userinfo.profile'; // See https://developers.google.com/youtube/v3/guides/auth/server-side-web-apps#identify-access-scopes
	const ACCESS_TYPE = 'offline';

	function __construct() {
		parent::__construct();
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__YOUTUBE_KEY' )
		&&
			defined( 'KEYRING__YOUTUBE_SECRET' )
		) {
			return array(
				'redirect_uri' => defined( 'KEYRING__YOUTUBE_URI' ) ? constant( 'KEYRING__YOUTUBE_URI' ) : '', // optional
				'key'          => constant( 'KEYRING__YOUTUBE_KEY' ),
				'secret'       => constant( 'KEYRING__YOUTUBE_SECRET' ),
			);
		} else {
			return null;
		}
	}

	function request_token_params( $params ) {
		$params['scope']       = self::SCOPE;
		$params['access_type'] = self::ACCESS_TYPE;
		$params['prompt']      = 'consent'; // Required to get a refresh token
		return $params;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_YouTube', 'init' ) );
