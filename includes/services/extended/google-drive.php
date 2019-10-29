<?php

/**
 * Google (Drive) service definition for Keyring.
 *
 * Drive API: https://developers.google.com/drive
 * OAuth implementation: https://developers.google.com/accounts/docs/OAuth2WebServer
 * App registration: https://console.developers.google.com/cloud-resource-manager
 */

class Keyring_Service_Google_Drive extends Keyring_Service_GoogleBase {
	const NAME        = 'google_drive';
	const LABEL       = 'Google Drive';
	const SCOPE       = 'profile https://www.googleapis.com/auth/drive.file'; // See https://developers.google.com/identity/protocols/googlescopes#sheetsv4
	const ACCESS_TYPE = 'offline';

	public function __construct() {
		// Publicize returns a bad name for this service so override the default
		add_filter( 'wpcom_get_keyring_connection_item', array( $this, 'modify_label' ) );

		parent::__construct();
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__GOOGLEDRIVE_KEY' ) &&
			defined( 'KEYRING__GOOGLEDRIVE_SECRET' )
		) {
			return array(
				'key'          => KEYRING__GOOGLEDRIVE_KEY,
				'secret'       => KEYRING__GOOGLEDRIVE_SECRET,
			);
		} else {
			return null;
		}
	}

	/**
	 * Return an appropriate text label for this service. Used by the 'wpcom_get_keyring_connection_item' filter
	 *
	 * @param array $service Array of service details (see WPCOM_External_Connections::format_keyring_connection_items)
	 * @return void
	 */
	function modify_label( $service ) {
		if ( $service['service'] === self::NAME ) {
			$service['label'] = self::LABEL;
		}

		return $service;
	}

	/**
	 * Returns a profile image for the connection
	 *
	 * Note we bump the size from 64x64 to 256x256
	 *
	 * @return mixed null on failure, or URL on success
	 */
	function fetch_profile_picture() {
		$image = false;
		$res = $this->request( $this->userinfo_url, array( 'method' => $this->self_method ) );

		if ( ! Keyring_Util::is_error( $res ) ) {
			$image = str_replace( 's64', 's256', $res->picture );
		}

		return empty( $image ) ? null : esc_url_raw( $image );
	}

}

add_action( 'keyring_load_services', array( 'Keyring_Service_Google_Drive', 'init' ) );

