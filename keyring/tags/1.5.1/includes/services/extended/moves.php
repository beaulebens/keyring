<?php

/**
 * Moves service definition for Keyring.
 * https://dev.moves-app.com/
 */

class Keyring_Service_Moves extends Keyring_Service_OAuth2 {
	const NAME  = 'moves';
	const LABEL = 'Moves';
	const SCOPE = 'activity location';

	function __construct() {
		parent::__construct();

		$this->place_types = array(
			'unknown'    => __( 'Unknown', 'keyring' ),
			'home'       => __( 'Home', 'keyring' ),
			'work'       => __( 'Work', 'keyring' ),
			'school'     => __( 'School', 'keyring' ),
			'user'       => __( 'Manually Named', 'keyring' ),
			'foursquare' => __( 'Selected from foursquare', 'keyring' ),
		);

		$this->activity_types = array(
			'wlk' => __( 'Walking', 'keyring' ),
			'cyc' => __( 'Cycling', 'keyring' ),
			'run' => __( 'Running', 'keyring' ),
			'trp' => __( 'Transport', 'keyring' ),
		);

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_moves_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_moves_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://api.moves-app.com/oauth/v1/authorize',    'GET'  );
		$this->set_endpoint( 'access_token', 'https://api.moves-app.com/oauth/v1/access_token', 'POST' );
		$this->set_endpoint( 'verify_token', 'https://api.moves-app.com/oauth/v1/tokeninfo',    'GET' );
		$this->set_endpoint( 'profile',      'https://api.moves-app.com/api/v1/user/profile',   'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;

		add_filter( 'keyring_moves_request_token_params', array( $this, 'request_token_params' ) );
	}

	function basic_ui_intro() {
		echo '<p>' . __( "Head over and <a href='https://dev.moves-app.com/apps/new'>create a new application</a> on Moves-app which you'll use to connect.", 'keyring' ) . '</p>';
		echo '<p>' . sprintf( __( "Once it's created, click the <strong>Development</strong> tab. Your <strong>App ID</strong> and <strong>API Key</strong> are both shown on that page as <strong>Client ID</strong>. Enter your <strong>Client secret</strong> in the <strong>API Secret</strong> box. On that tab there is also a <strong>Redirect URI</strong> box, which you should set to <code>%s</code>.", 'keyring' ), Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify' ) ) ) . '</p>';
	}

	function request_token_params( $params ) {
		$params['scope'] = apply_filters( 'keyring_moves_scope', self::SCOPE );
		return $params;
	}

	function build_token_meta( $token ) {
		$meta = array(
			'user_id'       => $token['user_id'],
			'refresh_token' => $token['refresh_token'],
			'expires'       => time() + $token['expires_in'],
			'_classname'    => get_called_class(),
		);

		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->profile_url );
		if ( !Keyring_Util::is_error( $response ) ) {
			$meta['first_date'] = $response->profile->firstDate;
		}

		return apply_filters( 'keyring_access_token_meta', $meta, self::NAME, $token, array(), $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'user_id' );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Moves', 'init' ) );
