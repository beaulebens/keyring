<?php

class Keyring_Token {
	var $name      = false;
	var $meta      = array();
	var $token     = false;
	var $service   = false;
	var $unique_id = false;
	
	function __construct( $service, $token, $meta = array(), $uniq = false ) {
		$this->name      = $service; // Name of the service this token is for
		$this->token     = $token;
		$this->unique_id = $uniq;
		foreach ( (array) $meta as $key => $val )
			$this->meta[ $key ] = $val[0];
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
			if ( is_string( $meta['classname'] ) && class_exists( $meta['classname'] ) ) {
				$this->service = $meta['classname']::init();
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
	
	function request( $url, $params = array() ) {
		$this->get_service();
		return $this->service->request( &$this, $url, $params );
	}
}
