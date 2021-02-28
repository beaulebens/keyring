<?php

/**
 * Twitter service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Twitter extends Keyring_Service_OAuth1 {
	const NAME  = 'twitter';
	const LABEL = 'Twitter';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_twitter_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_twitter_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->authorization_header = true;
		$this->authorization_realm  = 'twitter.com';

		$this->set_endpoint( 'request_token', 'https://twitter.com/oauth/request_token', 'POST' );
		$this->set_endpoint( 'authorize', 'https://twitter.com/oauth/authorize', 'GET' );
		$this->set_endpoint( 'access_token', 'https://twitter.com/oauth/access_token', 'POST' );
		$this->set_endpoint( 'verify', 'https://api.twitter.com/1.1/account/verify_credentials.json', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer         = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'If you haven\'t already, you\'ll need to <a href="%1$s">create an app on Twitter</a> (log in using your normal Twitter account). The <strong>Callback URL</strong> is <code>%2$s</code>.', 'keyring' ), 'https://apps.twitter.com/app/new', self_admin_url( 'tools.php' ) ) . '</p>';
		echo '<p>' . __( "Once you've created an app, copy and paste your <strong>Consumer key</strong> and <strong>Consumer secret</strong> (from under the <strong>OAuth settings</strong> section of your app's details) into the boxes below. You don't need an App ID for Twitter.", 'keyring' ) . '</p>';
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'  => $token['user_id'],
				'username' => $token['screen_name'],
				'name'     => $response->name,
				'picture'  => str_replace( '_normal.', '.', $response->profile_image_url ),
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return '@' . $token->get_meta( 'username' );
	}

	function test_connection() {
		$res = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		if ( ! Keyring_Util::is_error( $res ) ) {
			return true;
		}

		// Twitter may return a rate limiting error if the user accesses the sharing settings or post
		// page frequently. If so, ignore that error, things are likely aaaa-okay...
		$keyring_error_message = $res->get_error_message();
		if ( is_array( $keyring_error_message ) && isset( $keyring_error_message['response']['code'] ) ) {
			if ( 429 === absint( $keyring_error_message['response']['code'] ) ) {
				return true;
			}
		}

		return $res;
	}

	function fetch_profile_picture() {
		$res = $this->request( add_query_arg( array( 'user_id' => $this->token->get_meta( 'external_id' ) ), $this->user_info_url ), array( 'method' => $this->user_info_method ) );
		if ( Keyring_Util::is_error( $res ) ) {
			return $res;
		}

		return empty( $res->profile_image_url_https ) ? null : esc_url_raw( str_replace( '_normal', '', $res->profile_image_url_https ) ); // large size https://dev.twitter.com/overview/general/user-profile-images-and-banners
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Twitter', 'init' ) );
