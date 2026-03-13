<?php

/**
 * During the first phase of the auth flow, we normally want to (or are required to)
 * store some details before sending the user off to a remote service to grant access.
 * Use a request token to store those details locally, then we can retrieve them when
 * we get back to finish the auth flow.
 */
class Keyring_Request_Token extends Keyring_Token {
	public function __construct( $service, $token, $meta = array(), $uniq = false ) {
		$meta['type'] = 'request';
		parent::__construct( $service, $token, $meta, $uniq );
	}

	public function type() {
		return 'request';
	}
}
