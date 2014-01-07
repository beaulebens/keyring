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
			register_post_type( 'kr_request_token', array(
				'label'       => __( 'Keyring Request Token', 'keyring' ),
				'description' => __( 'Token or authentication details stored by Keyring. Request tokens are used during the authorization flow.', 'keyring' ),
				'public'      => false,
			) );

			register_post_type( 'kr_access_token', array(
				'label'       => __( 'Keyring Access Token', 'keyring' ),
				'description' => __( 'Token or authentication details stored by Keyring. Access tokens are used to make secure requests.', 'keyring' ),
				'public'      => false,
			) );

			$instance = new Keyring_SingleStore;
		}

		return $instance;
	}

	function insert( $token ) {
		// Avoid duplicates by checking to see if this exists already
		$found = get_posts( array(
			'numberposts' => 1,
			'post_type'   => 'kr_' . $token->type() . '_token',
			'meta_key'    => 'service',
			'meta_value'  => $token->get_name(),
			'author_id'   => get_current_user_id(),
			's'           => serialize( $token->token ), // Search the post content for this token
			'exact'       => true, // Require exact content match
		) );

		if ( $found ) {
			$token->unique_id = $found[0]->ID;
			return $this->update( $token );
		}

		$post = array(
			'post_type'    => 'kr_' . $token->type() . '_token',
			'post_status'  => 'publish',
			'post_content' => serialize( $token->token ),
		);
		$id = wp_insert_post( add_magic_quotes( $post ) );
		if ( $id ) {
			// Always record what service this token is for
			update_post_meta( $id, 'service', $token->get_name() );

			// Optionally include any meta related to this token
			foreach ( (array) $token->get_meta( false, true ) as $key => $val ) {
				update_post_meta( $id, $key, $val );
			}
			return $id;
		}
		return false;
	}

	function update( $token ) {
		if ( !$token->unique_id )
			return false;

		$id = $token->unique_id;
		$post = get_post( $id );
		if ( !$post )
			return false;

		$post->post_content = serialize( $token->token );
		wp_update_post( $post );

		foreach ( $token->get_meta( false, true ) as $key => $val ) {
			update_post_meta( $id, $key, $val );
		}

		return $id;
	}

	function delete( $args = array() ) {
		if ( !$args['id'] )
			return false;
		return wp_delete_post( $args['id'] );
	}

	function get_tokens( $args = array() ) {
		$defaults = array(
			'type'    => 'access',
			'service' => false,
			'user_id' => get_current_user_id(),
			'blog_id' => get_current_blog_id(),
		);
		$args = wp_parse_args( $args, $defaults );

		$query = array(
			'numberposts' => -1, // all
			'post_type'   => 'kr_' . $args['type'] . '_token',
			'author_id'   => $args['user_id'],
		);

		// Get tokens for a specific service
		if ( $args['service'] ) {
			$query['meta_key']   = 'service';
			$query['meta_value'] = $args['service'];
		}

		$token_type = 'request' == $args['type'] ? 'Keyring_Request_Token' : 'Keyring_Access_Token';
		$tokens = array();
		$posts = get_posts( $query );
		if ( count( $posts ) ) {
			foreach ( $posts as $post ) {
				$meta = get_post_meta( $post->ID );
				foreach ( $meta as $mid => $met ) {
					$meta[$mid] = $met[0];
				}

				$tokens[] = new $token_type(
					get_post_meta(
						$post->ID,
						'service',
						true
					),
					unserialize( $post->post_content ),
					$meta,
					$post->ID
				);
			}
		}

		return $tokens;
	}

	function get_token( $args = array() ) {
		$defaults = array(
			'id'      => false,
			'type'    => 'access',
			'service' => false,
			'user_id' => get_current_user_id(),
			'blog_id' => get_current_blog_id(),
		);
		$args = wp_parse_args( $args, $defaults );

		if ( !$args['id'] && !$args['service'] )
			return false;

		$post = get_post( $args['id'] );
		if ( $post ) {
			$meta = get_post_meta( $post->ID );
			foreach ( $meta as $mid => $met ) {
				$meta[$mid] = $met[0];
			}

			$token_type = 'kr_request_token' == $post->post_type ? 'Keyring_Request_Token' : 'Keyring_Access_Token';
			return new $token_type(
				get_post_meta(
					$post->ID,
					'service',
					true
				),
				unserialize( $post->post_content ),
				$meta,
				$post->ID
			);
		}
		return false;
	}

	function count( $args = array() ) {
		return count( $this->get_tokens( $args ) );
	}
}
