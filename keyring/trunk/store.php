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
	 *
	 * @param string $service The shortname of the service the token is for
	 * @param string $token The token itself, represented as a string
	 * @param string $meta An optional array containing any additional metadata to store with this token.
	 *                     Meta values with a leading "_" are considered "hidden" in core UI
	 */
	abstract function insert( $service, $token, $meta = array() );

	/**
	 * Update an existing token with a new token value and/or metadata.
	 *
	 * @param string $service The service to which the token we're updating belongs
	 * @param string $id A unique identifier (within this storage engine) for a specific token
	 * @param string $token The new token value (pass false to leave it unchanged)
	 * @param mixed $meta The new (array) meta values (pass false to leave it unchanged)
	 */
	abstract function update( $service, $id, $token = false, $meta = false );

	/**
	 * Delete a stored token permanently.
	 *
	 * @param string $service The service to which the token we're updating belongs
	 * @param string $id A unique identifier (within this storage engine) for a specific token
	 * @param mixed $meta Array of meta values that may help delete additional information for this token
	 */
	abstract function delete( $service, $id = false, $meta = false );

	/**
	 * Get an array of tokens for $service. If an $id is provided, then only get that single
	 * specific token (for the specified service). Include '_classname' corresponding
	 * to an existing Keyring_Service to auto-hydrate the ->service property
	 * when accessing a Token.
	 *
	 * @param string $service The service to which the token we're updating belongs
	 * @param string $id A unique identifier (within this storage engine) for a specific token. Leave as false to get all.
	 * @param mixed $meta Array of meta values that may help locate the desired tokens
	 * @return An array containing all tokens for a service, or a single token if $id is specified. False if none found.
	 */
	abstract function get_tokens( $service, $meta = false );

	/**
	 * Singular version of ::get_tokens(). Functions exactly the same, but
	 * only ever returns one token.
	 */
	abstract function get_token( $service, $id = false, $meta = false );

	/**
	 * Get all tokens within this storage engine.
	 *
	 * @param mixed $meta Array of meta to control what's returned, or false.
	 * @return Array containing all tokens for this engine, false if none.
	 */
	abstract function get_all_tokens( $meta = false );

	/**
	 * Get the number of tokens for a service
	 *
	 * @param mixed $service Name of a specific service, or false for all
	 * @param mixed $meta Array of meta to select specific tokens, or false for all
	 * @return Int containing the number of tokens matching the previous 2 params
	 */
	abstract function count( $service = false, $meta = false );
}

// Load all packaged token store engines in the ./includes/stores/ directory by including all PHP files
// Remove a Token Store (prevent it from loading at all) by filtering on 'keyring_token_stores'
$keyring_stores = glob( dirname( __FILE__ ) . "/includes/stores/*.php" );
$keyring_stores = apply_filters( 'keyring_token_stores', $keyring_stores );
foreach ( $keyring_stores as $keyring_store )
	require $keyring_store;
unset( $keyring_stores, $keyring_store );
