<?php

/**
 * Access tokens are what are 'permanently' stored, containing the information required
 * to make secure connections/requests on behalf of the user of a remote service.
 */
class Keyring_Access_Token extends Keyring_Token {
	public function __construct( $service, $token, $meta = array(), $uniq = false ) {
		$meta['type'] = 'access';
		parent::__construct( $service, $token, $meta, $uniq );
	}

	public function type() {
		return 'access';
	}
}
