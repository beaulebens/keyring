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
		return $this->token;
	}
	
	function get_uniq_id() {
		if ( isset( $this->unique_id ) )
			return $this->unique_id;
		return null;
	}
	
	function get_display() {
		if ( $service = $this->get_service() )
			return $service->get_display( &$this );
		return $this->name;
	}
	
	function get_service() {
		if ( !$this->service ) {
			$meta = $this->get_meta();
			if ( !empty( $meta['_classname'] ) && is_string( $meta['_classname'] ) && class_exists( $meta['_classname'] ) ) {
				$this->service = $meta['_classname']::init();
			}
		}
		return $this->service;
	}
	
	function get_service_name() {
		return $this->name;
	}
	
	function get_meta() {
		if ( isset( $this->meta ) )
			return $this->meta;
		return array();
	}
}
