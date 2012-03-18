<?php

/**
 * Facebook service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Facebook extends Keyring_Service {
	const NAME  = 'facebook';
	const LABEL = 'Facebook';

	function __construct( $details = array() ) {
		parent::__construct( $details );
		
		// Enable "basic" UI for entering key/secret
		add_action( 'keyring_facebook_manage_ui', array( $this, 'basic_ui' ) );
		
		if ( $creds = $this->get_credentials() ) {
			$this->app_id = $creds['key'];
			$this->secret = $creds['secret'];
		} else if ( defined( 'KEYRING__FACEBOOK_ID' ) && defined( 'KEYRING__FACEBOOK_SECRET' ) ) {
			$this->app_id = KEYRING__FACEBOOK_ID;
			$this->secret = KEYRING__FACEBOOK_SECRET;
		}
		
		$this->redirect_uri = Keyring_Util::admin_url( self::NAME, array( 'action' => 'verify' ) );
	}
	
	function request_token() {
		// Redirect to FB to handle logging in and authorizing
		wp_redirect( 'https://www.facebook.com/dialog/oauth?client_id=' . $this->app_id . '&redirect_uri=' . urlencode( $this->redirect_uri ) . '&scope=' . implode( ',', apply_filters( 'keyring_facebook_scope', array( 'offline_access', 'publish_stream' ) ) ) );
	}
	
	function get_display( $token ) {
	}
	
	function verify_token() {
		// Something went wrong
		if ( empty( $_GET['code'] ) ) {
			Keyring::error( __( 'A valid <code>code</code> was not returned from Facebook. Please try again in a minute.' ) );
			return;
		}
		
		// Use code to get an access token
		$res = wp_remote_get( "https://graph.facebook.com/oauth/access_token?client_id={$this->app_id}&redirect_uri=" . urlencode( $this->redirect_uri ) . "&client_secret={$this->secret}&code=" . $_GET['code'], array(
			'sslverify' => false,
		) );
		if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
			$token = wp_remote_retrieve_body( $res );
			parse_str( trim( $token ), $token );
			
			$res = wp_remote_get( "https://graph.facebook.com/me?access_token=" . $token['access_token'], array( 'sslverify' => false ) );
			if ( 200 == wp_remote_retrieve_response_code( $res ) ) {
				$res = wp_remote_retrieve_body( $res );
				$data = json_decode( $res );
				$this->store_token( $token['access_token'], array(
					'id' => $data->id,
					'username' => $data->username,
					'name' => $data->name,
					'link' => $data->link,
				) );
				wp_redirect( Keyring_Util::admin_url() );
				exit;
			} else {
				Keyring::error( __( 'Could not verify your Facebook profile information.' ) );
				return;
			}
		}
	}
	
	function request( $token, $url, $params = array() ) {
		// @todo
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Facebook', 'init' ) );
