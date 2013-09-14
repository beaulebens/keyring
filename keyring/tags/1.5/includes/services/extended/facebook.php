<?php

/**
 * Facebook service definition for Keyring. Clean implementation of OAuth2
 */

class Keyring_Service_Facebook extends Keyring_Service_OAuth2 {
	const NAME  = 'facebook';
	const LABEL = 'Facebook';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_facebook_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_facebook_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',     'https://www.facebook.com/dialog/oauth',        'GET' );
		$this->set_endpoint( 'access_token', 'https://graph.facebook.com/oauth/access_token', 'GET' );
		$this->set_endpoint( 'self',         'https://graph.facebook.com/me',                 'GET' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$kr_nonce = wp_create_nonce( 'keyring-verify' );
		$nonce    = wp_create_nonce( 'keyring-verify-facebook' );
		$this->redirect_uri = Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify', 'kr_nonce' => $kr_nonce, 'nonce' => $nonce, ) );

		$this->requires_token( true );

		add_filter( 'keyring_facebook_request_token_params', array( $this, 'filter_request_token' ) );
	}

	function basic_ui_intro() {
		echo '<p>' . __( "If you haven't already, you'll need to set up an app on Facebook:", 'keyring' ) . '</p>';
		echo '<ol>';
		echo '<li>' . __( "Click <strong>+ Create New App</strong> at the top-right of <a href='https://developers.facebook.com/apps'>this page</a>", 'keyring' ) . '</li>';
		echo '<li>' . __( "Enter a name for your app (maybe the name of your website?) and click <strong>Continue</strong> (ignore the other settings)", 'keyring' ) . '</li>';
		echo '<li>' . __( "Enter whatever is in the CAPTCHA and click <strong>Continue</strong>", 'keyring' ) . '</li>';
		echo '<li>' . sprintf( __( "Put your domain name in the <strong>App Domains</strong> box. That value is probably <code>%s</code>", 'keyring' ), $_SERVER['HTTP_HOST'] ) . '</li>';
		echo '<li>' . sprintf( __( "Click the <strong>Website with Facebook Login</strong> box and enter the URL to your website, which is probably <code>%s</code>", 'keyring' ), get_bloginfo( 'url' ) ) . '</li>';
		echo '<li>' . __( "Click <strong>Save Changes</strong>", 'keyring' ) . '</li>';
		echo '</ol>';
		echo '<p>' . __( "Once you're done configuring your app, copy and paste your <strong>App ID</strong> and <strong>App Secret</strong> (in the top section of your app's Basic details) into the appropriate fields below. Leave the App Key field blank.", 'keyring' ) . '</p>';
	}

	function _get_credentials() {
		if (
			defined( 'KEYRING__FACEBOOK_ID' )
		&&
			defined( 'KEYRING__FACEBOOK_SECRET' )
		) {
			return array(
				'app_id' => constant( 'KEYRING__FACEBOOK_ID' ),
				'key'    => constant( 'KEYRING__FACEBOOK_ID' ),
				'secret' => constant( 'KEYRING__FACEBOOK_SECRET' ),
			);
		} else {
			$all = apply_filters( 'keyring_credentials', get_option( 'keyring_credentials' ) );
			if ( !empty( $all['facebook'] ) ) {
				$creds = $all['facebook'];
				$creds['key'] = $creds['app_id'];
				return $creds;
			}

			// Return null to allow fall-thru to checking generic constants + DB
			return null;
		}
	}

	function is_configured() {
		$credentials = $this->get_credentials();
		return !empty( $credentials['app_id'] ) && !empty( $credentials['secret'] );
	}

	/**
	 * Add scope to the outbound URL, and allow developers to modify it
	 * @param  array $params Core request parameters
	 * @return Array containing originals, plus the scope parameter
	 */
	function filter_request_token( $params ) {
		if ( $scope = implode( ',', apply_filters( 'keyring_facebook_scope', array() ) ) )
			$params['scope'] = $scope;
		return $params;
	}

	/**
	 * Facebook decided to make things interesting and mix OAuth1 and 2. They return
	 * their access tokens using query string encoding, so we handle that here.
	 */
	function parse_access_token( $token ) {
		parse_str( $token, $token );
		return $token;
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'username' => $response->username,
				'user_id'  => $response->id,
				'name'     => $response->name,
				'picture'  => "https://graph.facebook.com/{$response->id}/picture?type=large",
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'facebook', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function test_connection() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( !Keyring_Util::is_error( $res ) )
			return true;

		return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Facebook', 'init' ) );
