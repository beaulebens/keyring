<?php

/**
 * LinkedIn service definition for Keyring. Clean implementation of OAuth2
 */

class Keyring_Service_LinkedIn extends Keyring_Service_OAuth2 {
	const NAME  = 'linkedin';
	const LABEL = 'LinkedIn';

	var $person = array();

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_linkedin_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_linkedin_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize', 'https://www.linkedin.com/oauth/v2/authorization', 'GET' );
		$this->set_endpoint( 'access_token', 'https://www.linkedin.com/oauth/v2/accessToken', 'POST' );
		$this->set_endpoint( 'self', 'https://api.linkedin.com/v2/me', 'GET' );
		$this->set_endpoint( 'profile_pic', 'https://api.linkedin.com/v2/me/picture-urls::(original)/', 'GET' );

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['app_id'];
			$this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->consumer             = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method     = new OAuthSignatureMethod_HMAC_SHA1;
		$this->authorization_header = 'Bearer';

		add_filter( 'keyring_' . self::NAME . '_request_scope', array( $this, 'member_permissions' ) );
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>' . sprintf( __( "To connect to LinkedIn, you'll first need to <a href='%s'>create an app</a>. A lot of the details are required, but they're not actually important to the operation of your app, since Keyring will override any important settings.", 'keyring' ), 'https://www.linkedin.com/secure/developer?newapp=' ) . '</p>';
		echo '<p>' . __( "Once you've created your app, go down to the <strong>Auth</strong> section and copy the <strong>Client ID</strong> value into the <strong>API Key</strong> field below, and the <strong>Client Secret</strong> value into the <strong>API Secret</strong> field", 'keyring' ) . '</p>';
		/* translators: url */
		echo '<p>' . sprintf( __( 'In the LinkedIn <strong>Redirect URLs:</strong> box, enter the URL <code>%s</code>.', 'keyring' ), Keyring_Util::admin_url( $this->get_name(), array( 'action' => 'verify' ) ) ) . '</p>';
		echo '<p>' . __( "Then click save (you don't need an App ID value for LinkedIn).", 'keyring' ) . '</p>';
	}

	/**
	 * Add in the `scope` parameter when authorizing.
	 * r_liteprofile   Grants access to first name, last name, id, and profile picture.
	 * w_member_social Grants access to post on behalf of the user.
	 *
	 * @param string $scope
	 * @return string
	 */
	function member_permissions( $scope ) {
		$scope = 'r_liteprofile w_member_social';
		return $scope;
	}

	/**
	 * By adding the `x-li-format: json` header here, we can avoid having to append `?format=json` to all requests.
	 *
	 * https://developer.linkedin.com/docs/rest-api#hero-par_longformtext_4_longform-text-content-par_resourceparagraph
	 *
	 * @param string $url
	 * @param array $params
	 * @return array|Keyring_Error|mixed|object|string
	 */
	function request( $url, array $params = array() ) {
		$params['headers']['x-li-format'] = 'json';
		return parent::request( $url, $params );
	}

	/**
	 * Build the meta for the token.
	 *
	 * @param mixed $token
	 * @return false|int|mixed
	 */
	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);

		$response = $this->request(
			$this->self_url . '?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))',
			array( 'method' => $this->self_method )
		);

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$this->person = $response;

			$first_name = $this->person->firstName;
			$last_name  = $this->person->lastName;
			$lfirst     = "{$first_name->preferredLocale->language}_{$first_name->preferredLocale->country}";
			$llast      = "{$last_name->preferredLocale->language}_{$last_name->preferredLocale->country}";

			$profile_picture = $this->person->profilePicture;

			$meta = array(
				'user_id' => $this->person->id,
				'name'    => $first_name->localized->{$lfirst} . ' ' . $last_name->localized->{$llast},
				'picture' => $profile_picture->{'displayImage~'}->elements[0]->identifiers[0]->identifier,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, self::NAME, $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	/**
	 * Get profile picture.
	 *
	 * @return string|mixed
	 */
	function fetch_profile_picture() {
		$response = $this->request(
			$this->self_url . '?projection=(profilePicture(displayImage~:playableStreams))',
			array( 'method' => $this->self_method )
		);

		if ( Keyring_Util::is_error( $response ) ) {
			return new WP_Error( 'missing-profile_picture', __( 'Could not find profile picture.', 'keyring' ) );
		}

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName
		return $response->profilePicture->{'displayImage~'}->elements[0]->identifiers[0]->identifier;
	}

	/**
	 * Test whether the connection has not been voided or expired.
	 *
	 * @return array|bool|Keyring_Error|mixed|object|string
	 */
	function test_connection() {
		$res = $this->request(
			$this->self_url,
			array( 'method' => $this->self_method )
		);
		if ( ! Keyring_Util::is_error( $res ) ) {
			return true;
		}
		return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_LinkedIn', 'init' ) );
