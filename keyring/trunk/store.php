<?php

/**
 * Template for creating a Keyring Token Store. All storage engines
 * should extend this. These engines are used for storing and managing
 * authentication tokens for remote Services.
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
	 * @param string $meta An optional array containing any additional metadata to store with this token
	 */
	abstract function insert( $service, $token, $meta = array() );
	
	/**
	 * Update an existing token with a new token value and/or metadata.
	 *
	 * @param string $service The service to which the token we're updating belongs
	 * @param string $id A unique identifier (within this storage engine) for a specific token
	 * @param string $token The new token value (pass false to leave it unchanged)
	 * @param string $meta The new meta value (pass false to leave it unchanged)
	 */
	abstract function update( $service, $id, $token = false, $meta = false );
	
	/**
	 * Delete a stored token permanently.
	 *
	 * @param string $service The service to which the token we're updating belongs
	 * @param string $id A unique identifier (within this storage engine) for a specific token
	 */
	abstract function delete( $service, $id = false );
	
	/**
	 * Get an array of tokens for $service. If an $id is provided, then only get that single
	 * specific token (for the specified service).
	 *
	 * @param string $service The service to which the token we're updating belongs
	 * @param string $id A unique identifier (within this storage engine) for a specific token
	 * @return An array containing all tokens for a service, or a single token if $id is specified. False if none found.
	 */
	abstract function get_tokens( $service, $id = false );
	
	/**
	 * Get an array containing all tokens stored within this storage engine.
	 *
	 * @return Array containing all stored tokens. Array will be empty if none are stored.
	 */
	abstract function get_all();
	
	abstract function count( $service );
}

/**
 * Token storage for a normal, single-blog installation.
 * Use CPT because that's what we have available to us and it's easy.
 */
class Keyring_SingleStore extends Keyring_Store {
	var $unique_id = false;
	
	static function &init() {
		static $instance = false;
		
		if ( !$instance ) {
			register_post_type( 'keyring_token', array(
				'label' => 'Keyring Token',
				'description' => __( 'Token or authentication details stored by Keyring', 'keyring' ),
				'public' => false,
			) );
		
			$instance = new Keyring_SingleStore;
		}
		
		return $instance;
	}
	
	function insert( $service, $token, $meta = array() ) {
		$post = array(
			'post_type' => 'keyring_token',
			'post_status' => 'publish',
			'post_content' => $token,
		);
		$id = wp_insert_post( add_magic_quotes( $post ) );
		if ( $id ) {
			// Always record what service this token is for
			update_post_meta( $id, 'service', $service );
			
			// Optionally include any meta related to this token
			foreach ( (array) $meta as $key => $val ) {
				update_post_meta( $id, $key, $val );
			}
			return $id;
		}
		return false;
	}
	
	function update( $service, $id, $token = false, $meta = false ) {
		// @todo token singlestore update
	}
	
	function delete( $service, $id = false ) {
		return wp_delete_post( $id );
	}
	
	function get_tokens( $service, $id = false ) {
		$return = array();
		if ( $id && $post = get_post( $id ) ) {
			$return[] = new Keyring_Token(
				get_post_meta(
					$post->ID,
					'service',
					true
				),
				$post->post_content,
				get_metadata(
					'post',
					$post->ID,
					'',
					true
				),
				$post->ID
			);
		} else {
			$posts = get_posts( array(
				'numberposts' => 999999,
				'post_type' => 'keyring_token',
				'meta_key' => 'service',
				'meta_value' => $service,
				'author_id' => get_current_user_id(),
			) );
			if ( count( $posts ) ) {
				foreach ( $posts as $post ) {
					$return[] = new Keyring_Token(
						get_post_meta(
							$post->ID,
							'service',
							true
						),
						$post->post_content,
						get_metadata(
							'post',
							$post->ID,
							'',
							true
						),
						$post->ID
					);
				}
			}
		}
		
		return $return;
	}
	
	function get_all( $args = array() ) {
		$posts = get_posts( array(
			'numberposts' => 999999,
			'post_type' => 'keyring_token',
			'post_author' => get_current_user_id(),
		) );
		$posts = wp_parse_args( $args, $posts );
		$return = array();
		if ( count( $posts ) ) {
			foreach ( $posts as $post ) {
				$return[] = new Keyring_Token(
					get_post_meta(
						$post->ID,
						'service',
						true
					),
					$post->post_content,
					get_metadata(
						'post',
						$post->ID,
						'',
						true
					),
					$post->ID
				);
			}
		}
		return $return;
	}
	
	function count( $service ) {
		return count( $this->get_tokens( $service, false ) );
	}
}

