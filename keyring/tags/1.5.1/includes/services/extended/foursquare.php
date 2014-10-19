<?php

/**
 * Foursquare service definition for Keyring.
 * https://developer.foursquare.com/docs/oauth.html
 * https://foursquare.com/oauth/
 */

class Keyring_Service_Foursquare extends Keyring_Service_OAuth2 {
	const NAME  = 'foursquare';
	const LABEL = 'Foursquare';

	const API_VERSION = '20120701';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_foursquare_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_foursquare_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://foursquare.com/oauth2/authenticate', 'GET' );
		$this->set_endpoint( 'access_token', 'https://foursquare.com/oauth2/access_token', 'GET' );
		$this->set_endpoint( 'self',         'https://api.foursquare.com/v2/users/self',   'GET' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;
	}

	function basic_ui_intro() {
		echo '<p>' . __( "If you haven't already, you'll need to <a href='https://foursquare.com/developers/register'>create a new app at Foursquare</a>. You should only need to worry about these settings:", 'keyring' ) . '</p>';
		echo '<ol>';
		echo '<li>' . __( "<strong>Your app name</strong>: enter whatever you like, maybe your website's name?", 'keyring' ) . '</li>';
		echo '<li>' . sprintf( __( "<strong>Download / welcome page url</strong>: just enter your website's URL, <code>%s</code>", 'keyring' ), get_bloginfo( 'url' ) ) . '</li>';
		echo '<li>' . sprintf( __( "<strong>Redirect URI(s)</strong>: Copy-paste this, <code>%s</code>", 'keyring' ), Keyring_Util::admin_url( 'foursquare', array( 'action' => 'verify' ) ) ) . '</li>';
		echo '<li>' . __( "<strong>New users can connect via the web</strong>: check the box", 'keyring' ) . '</li>';
		echo '</ol>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>Client id</strong> value into the <strong>API Key</strong> field, and the <strong>Client secret</strong> value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Foursquare).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$token = new Keyring_Access_Token( $this->get_name(), $token['access_token'], array() );
		$this->set_token( $token );
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( Keyring_Util::is_error( $res ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'    => $res->response->user->id,
				'first_name' => $res->response->user->firstName,
				'last_name'  => $res->response->user->lastName,
				'picture'    => $res->response->user->photo->prefix . '300x300' . $res->response->user->photo->suffix,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'foursquare', $token, $res, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		$meta = $token->get_meta();
		return trim( $meta['first_name'] . ' ' . $meta['last_name'] );
	}

	function request( $url, array $params = array() ) {
		$url = add_query_arg( array( 'v' => self::API_VERSION ), $url );
		return parent::request( $url, $params );
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Foursquare', 'init' ) );
