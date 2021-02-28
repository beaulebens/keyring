<?php

/**
 * Tumblr service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Tumblr extends Keyring_Service_OAuth1 {
	const NAME  = 'tumblr';
	const LABEL = 'Tumblr';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_tumblr_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_tumblr_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'request_token', 'https://www.tumblr.com/oauth/request_token', 'POST' );
		$this->set_endpoint( 'authorize', 'https://www.tumblr.com/oauth/authorize', 'GET' );
		$this->set_endpoint( 'access_token', 'https://www.tumblr.com/oauth/access_token', 'POST' );
		$this->set_endpoint( 'self', 'https://api.tumblr.com/v2/user/info', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer         = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header = true; // Send OAuth token in the header, not querystring
		$this->authorization_realm  = 'tumblr.com';
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'To get started, <a href="%1$s">register an application with Tumblr</a>. The <strong>Default callback URL</strong> should be set to <code>%2$s</code>, and you can enter whatever you like in the other fields.', 'keyring' ), 'https://www.tumblr.com/oauth/register', Keyring_Util::admin_url( 'tumblr', array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Once you've created your app, copy the <strong>OAuth Consumer Key</strong> into the <strong>API Key</strong> field below. Click the <strong>Show secret key</strong> link, and then copy the <strong>Secret Key</strong> value into the <strong>API Secret</strong> field below. You don't need an App ID value for Tumblr.", 'keyring' ) . '</p>';
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				'tumblr',
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( 'https://api.tumblr.com/v2/user/info', array( 'method' => 'GET' ) );

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$this->person = $response->response->user;
			$meta         = array(
				'name' => $this->person->name,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
			$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( ! Keyring_Util::is_error( $res ) ) {
			return true;
		}

			return $res;
	}

	function fetch_profile_picture() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( empty( $res ) || is_wp_error( $res ) ) {
			return null;
		}

		foreach ( $res->response->user->blogs as $blog ) {
			if ( ! $blog->primary ) {
				continue;
			}
			return $this->fetch_profile_picture_for_blog( $blog );
		}

		return null;
	}

	function fetch_primary_blog() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( empty( $res ) || is_wp_error( $res ) ) {
			return null;
		}

		foreach ( $res->response->user->blogs as $blog ) {
			if ( ! $blog->primary ) {
				continue;
			}

			$blog_basename = parse_url( $blog->url, PHP_URL_HOST );

			$primary_tumblr_blog = array(
				'id'       => $blog_basename,
				'name'     => $blog->title,
				'category' => $blog->type,
				'url'      => $blog->url,
				'picture'  => $this->fetch_profile_picture_for_blog( $blog ),
			);

			return (object) $primary_tumblr_blog;
		}

		return false;
	}

	function fetch_additional_external_users() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( empty( $res ) || is_wp_error( $res ) ) {
			return null;
		}

		$additional_external_users = array();

		foreach ( $res->response->user->blogs as $blog ) {
			if ( $blog->primary ) {
				continue;
			}

			$blog_basename = parse_url( $blog->url, PHP_URL_HOST );

			$this_tumblr_blog = array(
				'id'       => $blog_basename,
				'name'     => $blog->title,
				'category' => $blog->type,
				'url'      => $blog->url,
				'picture'  => $this->fetch_profile_picture_for_blog( $blog ),
			);

			$additional_external_users[] = (object) $this_tumblr_blog;
		}

		return $additional_external_users;
	}

	function fetch_profile_picture_for_blog( $blog ) {
		// unfortunately tumblr's API does not allow the retrieval
		// of avatars for private blogs...
		if ( 'private' === $blog->type ) {
			return null;
		}
		$blog_basename = parse_url( $blog->url, PHP_URL_HOST );
		return esc_url_raw( sprintf( 'https://api.tumblr.com/v2/blog/%s/avatar/512', $blog_basename ) );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Tumblr', 'init' ) );
