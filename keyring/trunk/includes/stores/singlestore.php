<?php

/**
 * Token storage for a normal, single-blog installation. Works with multiple
 * users, but not recommended for a Multi-Site install (see multistore.php)
 * Uses CPT because that's what we have available to us and it's easy.
 * 
 * @package Keyring
 */
class Keyring_SingleStore extends Keyring_Store {
	var $unique_id = false;
	
	static function &init() {
		static $instance = false;
		
		if ( !$instance ) {
			register_post_type( 'keyring_token', array(
				'label' => __( 'Keyring Token', 'keyring' ),
				'description' => __( 'Token or authentication details stored by Keyring', 'keyring' ),
				'public' => false,
			) );
		
			$instance = new Keyring_SingleStore;
		}
		
		return $instance;
	}
	
	function insert( $service, $token, $meta = array() ) {
		// Avoid duplicates
		$found = get_posts( array(
			'numberposts' => 1,
			'post_type' => 'keyring_token',
			'meta_key' => 'service',
			'meta_value' => $service,
			'author_id' => get_current_user_id(),
			's' => maybe_serialize( $token ), // Search the post content for this token
			'exact' => true, // Require exact content match
		) );
		
		if ( $found ) {
			$this->update( $service, $found[0]->ID, $token, $meta );
			return $found[0]->ID;
		}
		
		$post = array(
			'post_type' => 'keyring_token',
			'post_status' => 'publish',
			'post_content' => maybe_serialize( $token ),
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
		// TODO token singlestore update
	}
	
	function delete( $service, $id = false, $meta = false ) {
		return wp_delete_post( $id );
	}
	
	function get_tokens( $service, $meta = false ) {
		$return = array();
		$posts = get_posts( array(
			'numberposts' => -1,
			'post_type' => 'keyring_token',
			'meta_key' => 'service',
			'meta_value' => $service,
			'author_id' => get_current_user_id(),
		) );
		if ( count( $posts ) ) {
			foreach ( $posts as $post ) {
				$meta = get_post_meta( $post->ID );
				foreach ( $meta as $mid => $met ) {
					$meta[$mid] = $met[0];
				}
				
				$return[] = new Keyring_Token(
					get_post_meta(
						$post->ID,
						'service',
						true
					),
					maybe_unserialize( $post->post_content ),
					$meta,
					$post->ID
				);
			}
		}
		
		return $return;
	}
	
	function get_token( $service, $id = false, $meta = false ) {
		$post = get_post( $id );
		if ( $post ) {
			$meta = get_post_meta( $post->ID );
			foreach ( $meta as $mid => $met ) {
				$meta[$mid] = $met[0];
			}
			
			return new Keyring_Token(
				get_post_meta(
					$post->ID,
					'service',
					true
				),
				maybe_unserialize( $post->post_content ),
				$meta,
				$post->ID
			);
		}
		return false;
	}
	
	function get_all_tokens( $meta = false ) {
		$posts = get_posts( array(
			'numberposts' => -1,
			'post_type' => 'keyring_token',
			'post_author' => get_current_user_id(),
		) );
		$return = array();
		if ( count( $posts ) ) {
			foreach ( $posts as $post ) {
				// Get all metadata and reformat so it's a flat array
				$meta = get_post_meta( $post->ID );
				foreach ( $meta as $mid => $met ) {
					$meta[$mid] = $met[0];
				}
				
				// Build out our token, with meta
				$return[] = new Keyring_Token(
					get_post_meta(
						$post->ID,
						'service',
						true
					),
					maybe_unserialize( $post->post_content ),
					$meta,
					$post->ID
				);
			}
		}
		return $return;
	}
	
	function count( $service = false, $meta = false ) {
		if ( $service )
			return count( $this->get_tokens( $service, $meta ) );
		else
			return count( $this->get_all_tokens( $meta ) );
	}
}
