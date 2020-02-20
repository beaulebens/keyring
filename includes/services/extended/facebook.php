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

		$this->set_endpoint( 'authorize', 'https://www.facebook.com/v2.9/dialog/oauth', 'GET' );
		$this->set_endpoint( 'access_token', 'https://graph.facebook.com/v2.9/oauth/access_token', 'GET' );
		$this->set_endpoint( 'self', 'https://graph.facebook.com/v2.9/me', 'GET' );
		$this->set_endpoint( 'profile_pic', 'https://graph.facebook.com/v2.9/me/picture/?redirect=false&width=150&height=150', 'GET' );

		$creds        = $this->get_credentials();
		$this->app_id = $creds['app_id'];
		$this->key    = $creds['key'];
		$this->secret = $creds['secret'];

		$kr_nonce           = wp_create_nonce( 'keyring-verify' );
		$nonce              = wp_create_nonce( 'keyring-verify-facebook' );
		$this->redirect_uri = Keyring_Util::admin_url(
			self::NAME,
			array(
				'action'   => 'verify',
				'kr_nonce' => $kr_nonce,
				'nonce'    => $nonce,
			)
		);

		$this->requires_token( true );

		add_filter( 'keyring_facebook_request_token_params', array( $this, 'filter_request_token' ) );
	}

	function basic_ui_intro() {
		echo '<p>' . __( "If you haven't already, you'll need to set up an app on Facebook:", 'keyring' ) . '</p>';
		echo '<ol>';
		/* translators: url */
		echo '<li>' . sprintf( __( "Click <strong>+ Create New App</strong> at the top-right of <a href='%s'>this page</a>", 'keyring' ), 'https://developers.facebook.com/apps' ) . '</li>';
		echo '<li>' . __( 'Enter a name for your app (maybe the name of your website?) and a Category, click <strong>Continue</strong> (you can skip optional things)', 'keyring' ) . '</li>';
		echo '<li>' . __( 'Enter whatever is in the CAPTCHA and click <strong>Continue</strong>', 'keyring' ) . '</li>';
		/* translators: url */
		echo '<li>' . sprintf( __( 'Click <strong>Settings</strong> on the left and then <strong>Advanced</strong> at the top of that page. Under <strong>Valid OAuth redirect URIs</strong>, enter your domain name. That value is probably <code>%s</code>', 'keyring' ), $_SERVER['HTTP_HOST'] ) . '</li>';
		/* translators: url */
		echo '<li>' . sprintf( __( 'Click the <strong>Website with Facebook Login</strong> box and enter the URL to your website, which is probably <code>%s</code>', 'keyring' ), get_bloginfo( 'url' ) ) . '</li>';
		echo '<li>' . __( 'Click <strong>Save Changes</strong>', 'keyring' ) . '</li>';
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
			if ( ! empty( $all['facebook'] ) ) {
				$creds        = $all['facebook'];
				$creds['key'] = $creds['app_id'];
				return $creds;
			}

			// Return null to allow fall-thru to checking generic constants + DB
			return null;
		}
	}

	function is_configured() {
		$credentials = $this->get_credentials();
		return ! empty( $credentials['app_id'] ) && ! empty( $credentials['secret'] );
	}

	/**
	 * Add scope to the outbound URL, and allow developers to modify it
	 * @param  array $params Core request parameters
	 * @return Array containing originals, plus the scope parameter
	 */
	function filter_request_token( $params ) {
		$scope = implode( ',', apply_filters( 'keyring_facebook_scope', array() ) );
		if ( $scope ) {
			$params['scope'] = $scope;
		}
		return $params;
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
				'user_id' => $response->id,
				'name'    => $response->name,
				'picture' => "https://graph.facebook.com/v2.9/{$response->id}/picture?type=large",
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

	/**
	 * Get a list of FB Pages that this user has permissions to manage
	 * @param  Keyring_Token $connection A connection to FB.
	 * @return Array containing the raw results for each page, or empty if none.
	 */
	function get_fb_pages( $connection = false ) {
		if ( $connection ) {
			$this->set_token( $connection );
		}

		$additional_external_users = array();
		$fb_accounts               = $this->request( 'https://graph.facebook.com/v2.9/me/accounts/' );
		if ( ! empty( $fb_accounts ) && ! is_wp_error( $fb_accounts ) ) {
			foreach ( $fb_accounts->data as $fb_account ) {
				if ( empty( $fb_account->access_token ) ) {
					continue;
				}

				// Must request page with access token from /me/accounts,
				// otherwise can_post returns as voice of user, not page
				$fb_account_url = 'https://graph.facebook.com/v2.9/' . urlencode( $fb_account->id );
				$fb_account_url = add_query_arg(
					array(
						'access_token' => $fb_account->access_token,
						'fields'       => 'is_published,can_post,id,name,category,picture',
					),
					$fb_account_url
				);
				$fb_page        = $this->request( $fb_account_url );

				// only continue with this account as a viable option if we can post content to it
				if ( ! $fb_page->is_published || ! $fb_page->can_post ) {
					continue;
				}

				$this_fb_page = array(
					'id'           => $fb_page->id,
					'name'         => $fb_page->name,
					'access_token' => $fb_account->access_token,
					'category'     => $fb_page->category,
					'picture'      => null,
				);

				if ( ! empty( $fb_page->picture ) && ! empty( $fb_page->picture->data ) ) {
					$this_fb_page['picture'] = esc_url_raw( $fb_page->picture->data->url );
				}

				$additional_external_users[] = (object) $this_fb_page;
			}
		}

		return $additional_external_users;
	}

	function fetch_additional_external_users() {
		return $this->get_fb_pages();
	}

	function fetch_profile_picture() {
		$res = $this->request( $this->profile_pic_url, array( 'method' => $this->profile_pic_method ) );
		return empty( $res->data->url ) ? null : esc_url_raw( $res->data->url );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Facebook', 'init' ) );
