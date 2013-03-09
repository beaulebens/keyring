<?php

/**
 * Template for creating a Keyring Token Store. All storage engines
 * MUST extend this. These engines are used for storing and managing
 * authentication tokens for remote Services. Use $meta to handle any
 * custom requirements (access v request tokens, scope, etc)
 *
 * @package Keyring
 */
abstract class Keyring_Store {
	/**
	 * Any set up required to initiate this storage engine.
	 */
	abstract static function &init();

	/**
	 * Insert a new token into this storage engine.
	 */
	abstract function insert( $token );

	/**
	 * Update an existing token with a new token value and/or metadata.
	 */
	abstract function update( $token );

	/**
	 * Delete a token, or tokens.
	 */
	abstract function delete( $args = array() );

	/**
	 * Get an array of tokens for $service. If an $id is provided, then only get that single
	 * specific token (for the specified service).
	 */
	abstract function get_tokens( $args = array() );

	/**
	 * Singular version of ::get_tokens(). Functions exactly the same, but
	 * only ever returns one token.
	 */
	abstract function get_token( $args = array() );

	/**
	 * Get the number of tokens for a service
	 */
	abstract function count( $args = array() );
}

// Load all packaged token store engines in the ./includes/stores/ directory by including all PHP files
// Remove a Token Store (prevent it from loading at all) by filtering on 'keyring_token_stores'
$keyring_stores = glob( dirname( __FILE__ ) . "/includes/stores/*.php" );
$keyring_stores = apply_filters( 'keyring_token_stores', $keyring_stores );
foreach ( $keyring_stores as $keyring_store )
	require $keyring_store;
unset( $keyring_stores, $keyring_store );
