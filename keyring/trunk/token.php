<?php

/**
 * Keyring connection tokens all look the same, although they may have varying
 * amounts of information stuffed in their meta values. Store a meta value 
 * called "_classname" which contains the name of a Keyring_Service class to
 * use to "re-hydrate" the service this token is associated with.
 *
 * @package Keyring
 */
class Keyring_Token {
	var $name      = false;
	var $token     = false;
	var $meta      = array();
	var $service   = false; // Will contain a Keyring_Service object
	var $unique_id = false;
	
	function __construct( $service, $token, $meta = array(), $uniq = false ) {
		$this->name      = strtolower( $service ); // Name of the service this token is for
		$this->token     = $token;
		$this->unique_id = $uniq;
		foreach ( (array) $meta as $key => $val )
			$this->meta[ $key ] = $val;
		$this->get_service();
	}
	
	function __toString() {
		return (string) $this->token;
	}
	
	function get_uniq_id() {
		if ( isset( $this->unique_id ) )
			return $this->unique_id;
		return null;
	}
	
	function get_display() {
		if ( $service = $this->get_service() )
			return $service->get_display( $this );
		return $this->name;
	}
	
	function get_service() {
		if ( !$this->service ) {
			$class = $this->get_meta( '_classname', true );
			if ( $class && class_exists( $class ) ) {
				$this->service = call_user_func( array( $class, 'init' ) );
			}
		}
		return $this->service;
	}
	
	function get_service_name() {
		return $this->name;
	}
	
	/**
	 * Get a specific piece of meta data for this token, or all meta as an array.
	 *
	 * @param mixed $name The key name for a specific meta item, or false for all.
	 * @param bool $allow_hidden Allow access to "hidden" meta (prefixed with "_")
	 * @return Mixed meta value, array of meta values, or null
	 */
	function get_meta( $name = false, $allow_hidden = false ) {
		$return = null;
		if ( $name ) {
			if ( '_' != substr( $name, 0, 1 ) || $allow_hidden ) {
				if ( isset( $this->meta[ $name ] ) ) {
					$return = $this->meta[ $name ];
				}
			}
		} else {
			foreach ( (array) $this->meta as $key => $val ) {
				if ( '_' != substr( $key, 0, 1 ) || $allow_hidden ) {
					$return[ $key ] = $val;
				}
			}
		}

		return $return;
	}
	
	/**
	* Check if a token has expired, or will expire in the next $window seconds
	**/
	function is_expired( $window = 0 ) {
		if ( !$expires = $this->get_meta( 'expires' ) )
			return false; // No expires value, assume it's a permanent token
		
		if ( '0000-00-00 00:00:00' == $expires )
			return false; // Doesn't expire
		
		if ( ( time() + $window ) > strtotime( $expires ) )
			return true; // Token's expiry time has passed, or will pass before $window
		
		// Not expired
		return false;
	}
}
