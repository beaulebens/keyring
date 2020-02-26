<?php

/**
 * Token storage for a Multi-Site install. Works with multiple users, sharing
 * connections across multiple sites.
 *
 * Stores the tokens in CPTs, and the shared status as postmeta on those posts.
 *
 * @package Keyring
 */
class Keyring_MultiStore extends Keyring_Store {

	/**
	 * Initialises the store.
	 *
	 * @return Keyring_MultiStore The store instance.
	 */
	static function &init() {
		static $instance = false;

		if ( ! $instance ) {
			register_post_type(
				'kr_request_token',
				array(
					'label'       => __( 'Keyring Request Token', 'keyring' ),
					'description' => __( 'Token or authentication details stored by Keyring. Request tokens are used during the authorization flow.', 'keyring' ),
					'public'      => false,
				)
			);

			register_post_type(
				'kr_access_token',
				array(
					'label'       => __( 'Keyring Access Token', 'keyring' ),
					'description' => __( 'Token or authentication details stored by Keyring. Access tokens are used to make secure requests.', 'keyring' ),
					'public'      => false,
				)
			);

			$instance = new Keyring_MultiStore;
		}

		return $instance;
	}

	/**
	 * Inserts a new token in the store.
	 *
	 * @param Keyring_Token $token  The token being stored.
	 * @return int|false The unique ID assigned to the token, or false if it fails to save.
	 */
	function insert( $token ) {
		$site_id = get_current_blog_id();
		switch_to_blog( KEYRING__MULTI_STORE_SITE_ID );

		// Avoid duplicates by checking to see if this exists already
		$found = get_posts(
			array(
				'posts_per_page' => 1,
				'post_type'      => 'kr_' . $token->type() . '_token',
				'meta_key'       => 'service',
				'meta_value'     => $token->get_name(),
				'author'         => get_current_user_id(),
				's'              => serialize( $token->token ), // Search the post content for this token
				'exact'          => true, // Require exact content match
				'sentence'       => true, // Require to search by phrase, otherwise string is split by regex
			)
		);

		if ( $found ) {
			$token->unique_id = $found[0]->ID;
			restore_current_blog();
			return $this->update( $token, $shared );
		}

		$post = array(
			'post_type'    => 'kr_' . $token->type() . '_token',
			'post_status'  => 'publish',
			'post_content' => serialize( $token->token ),
		);
		$id   = wp_insert_post( add_magic_quotes( $post ) );
		if ( $id ) {
			// Always record what service this token is for
			update_post_meta( $id, 'service', $token->get_name() );

			// Record which site this token was created on, and if it was shared or not.
			update_post_meta( $id, "shared_$site_id", $shared );

			// Optionally include any meta related to this token
			foreach ( (array) $token->get_meta( false, true ) as $key => $val ) {
				update_post_meta( $id, $key, $val );
			}
			restore_current_blog();
			return $id;
		}
		restore_current_blog();
		return false;
	}

	/**
	 * Updated an existing token in the store.
	 *
	 * @param Keyring_Token $token  The token being stored.
	 * @return int|false The unique ID assigned to the token, or false if it fails to save.
	 */
	function update( $token ) {
		if ( ! $token->unique_id ) {
			return false;
		}

		$site_id = get_current_blog_id();
		switch_to_blog( KEYRING__MULTI_STORE_SITE_ID );

		$id   = $token->unique_id;
		$post = get_post( $id );
		if ( ! $post ) {
			restore_current_blog();
			return false;
		}

		$post->post_content = serialize( $token->token );
		wp_update_post( $post );

		// Record which site this token was updated on, and if it was shared or not.
		update_post_meta( $id, "shared_$site_id", $shared );

		foreach ( $token->get_meta( false, true ) as $key => $val ) {
			update_post_meta( $id, $key, $val );
		}

		restore_current_blog();
		return $id;
	}

	/**
	 * Deletes an existing token.
	 *
	 * @param array $args {
	 *     @type int $id The unique id of the token to delete.
	 * }
	 * @return WP_Post|false The post object of the token being deleted, or false if the delete failed.
	 */
	function delete( $args = array() ) {
		if ( ! $args['id'] ) {
			return false;
		}

		switch_to_blog( KEYRING__MULTI_STORE_SITE_ID );
		$post = wp_delete_post( $args['id'] );
		restore_current_blog();

		return $post;
	}

	/**
	 * Retrieve an array of tokens.
	 *
	 * @param array $args {
	 *     Parameters for selecting which tokens to retrieve.
	 *
	 *     @type string       $type    Optional. The token type to retrieve. Valid values are 'access',
	 *                                 and 'request'. Default 'access'.
	 *     @type string|false $service Optional. The name of the service to retrieve. To retrieve all services,
	 *                                 set to `false`. Default `false`.
	 *     @type int|false    $user_id Optional. Retrieve tokens belonging to this user. To retrieve tokens shared
	 *                                 with this site by any user, set to `false`. Defaults to the current user id.
	 *     @type int          $blog_id Optional. Retrieve tokens on this site.
	 * }
	 */
	function get_tokens( $args = array() ) {
		$defaults = array(
			'type'    => 'access',
			'service' => false,
			'user_id' => get_current_user_id(),
			'blog_id' => get_current_blog_id(),
		);
		$args     = wp_parse_args( $args, $defaults );

		$query = array(
			'numberposts' => -1, // all
			'post_type'   => 'kr_' . $args['type'] . '_token',
			'author'      => $args['user_id'],
		);

		// Get tokens for a specific service
		if ( $args['service'] ) {
			$query['meta_key']   = 'service';
			$query['meta_value'] = $args['service'];
		}

		$token_type = 'request' === $args['type'] ? 'Keyring_Request_Token' : 'Keyring_Access_Token';
		$tokens     = array();
		$posts      = get_posts( $query );
		if ( count( $posts ) ) {
			foreach ( $posts as $post ) {
				$meta = get_post_meta( $post->ID );
				foreach ( $meta as $mid => $met ) {
					$meta[ $mid ] = $met[0];
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
		$args     = wp_parse_args( $args, $defaults );

		if ( ! $args['id'] && ! $args['service'] ) {
			return false;
		}

		$post = get_post( $args['id'] );
		if ( $post ) {
			$meta = get_post_meta( $post->ID );
			foreach ( $meta as $mid => $met ) {
				$meta[ $mid ] = $met[0];
			}

			$token_type = 'kr_request_token' === $post->post_type ? 'Keyring_Request_Token' : 'Keyring_Access_Token';
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
