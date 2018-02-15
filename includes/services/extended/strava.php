<?php

/**
 * Strava service definition for Keyring, supporting the Strava API v3
 * https://developers.strava.com/
 */

class Keyring_Service_Strava extends Keyring_Service_OAuth2 {
	const NAME  = 'strava';
	const LABEL = 'Strava';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_strava_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_strava_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://www.strava.com/oauth/authorize',		'GET'  );
		$this->set_endpoint( 'access_token', 'https://www.strava.com/oauth/token',				'POST' );
		$this->set_endpoint( 'deauthorize',  'https://www.strava.com/oauth/deauthorize',	'POST' );
		$this->set_endpoint( 'user',         'https://www.strava.com/api/v3/athlete',			'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'You\'ll need to <a href="%s">create a new application</a> on Strava so that you can connect.', 'keyring' ), 'https://www.strava.com/settings/api' ) . '</p>';
		echo '<p>' . __( "Once you've registered your application, copy the <strong>Application Name</strong> into the <strong>App ID</strong>, the <strong>Client ID</strong> and the <strong>Client Secret</strong> into the <strong>API Key</strong> and <strong>API Secret</strong> fields below,.", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			/* Example response from https://www.strava.com/oauth/token
			{
			  "access_token": "83ebeabdec09f6670863766f792ead24d61fe3f9",
			  "athlete": {
			    "id": 227615,
			    "resource_state": 2,
			    "firstname": "John",
			    "lastname": "Applestrava",
			    "profile_medium": "http://pics.com/227615/medium.jpg",
			    "profile": "http://pics.com/227615/large.jpg",
			    "city": "San Francisco",
			    "state": "California",
			    "country": "United States",
			    "sex": "M",
			    "premium": true,
			    "email": "john@applestrava.com",
			    "created_at": "2008-01-01T17:44:00Z",
			    "updated_at": "2013-09-04T20:00:50Z"
			  }
			} */
			$meta = array( 'user_id' => (int) $response->id );

			// Now get the rest of their profile
			$profile = $this->request( $this->profile_url, array( 'method' => $this->profile_method ) );
			/* Example response from GET https://www.strava.com/api/v3/athlete
			{
			  "id": 227615,
			  "resource_state": 3,
			  "firstname": "John",
			  "lastname": "Applestrava",
			  "profile_medium": "http://pics.com/227615/medium.jpg",
			  "profile": "http://pics.com/227615/large.jpg",
			  "city": "San Francisco",
			  "state": "California",
			  "country": "United States",
			  "sex": "M",
			  "friend": null,
			  "follower": null,
			  "premium": true,
			  "created_at": "2008-01-01T17:44:00Z",
			  "updated_at": "2013-09-04T20:00:50Z",
			  "follower_count": 273,
			  "friend_count": 19,
			  "mutual_friend_count": 0,
			  "athlete_type": 0,
			  "date_preference": "%m/%d/%Y",
			  "measurement_preference": "feet",
			  "email": "john@applestrava.com",
			  "ftp": 280,
			  "weight": 68.7,
			  "clubs": [
			    {
			      "id": 1,
			      "resource_state": 2,
			      "name": "Team Strava Cycling",
			      "profile_medium": "http://pics.com/clubs/1/medium.jpg",
			      "profile": "http://pics.com/clubs/1/large.jpg",
			      "cover_photo": "http://pics.com/clubs/1/cover/large.jpg",
			      "cover_photo_small": "http://pics.com/clubs/1/cover/small.jpg",
			      "sport_type": "cycling",
			      "city": "San Francisco",
			      "state": "California",
			      "country": "United States",
			      "private": true,
			      "member_count": 23,
			      "featured": false,
			      "url": "strava-cycling"
			    }
			  ],
			  "bikes": [
			    {
			      "id": "b105763",
			      "primary": false,
			      "name": "Cannondale TT",
			      "distance": 476612.9,
			      "resource_state": 2
			    },
			    {
			      "id": "b105762",
			      "primary": true,
			      "name": "Masi",
			      "distance": 9000578.2,
			      "resource_state": 2
			    }
			  ],
			  "shoes": [
			    {
			      "id": "g1",
			      "primary": true,
			      "name": "Running Shoes",
			      "distance": 67492.9,
			      "resource_state": 2
			    }
			  ]
			} */
			if ( !Keyring_Util::is_error( $profile ) ) {
				$meta['firstname'] = $profile->firstname;
				$meta['lastname']     = $profile->lastname;
				$meta['picture']  = $profile->profile;
				$meta['first_date'] = $profile->created_at; // Capture the athlete's profile creation date for later use, eg: in keyring-social-importers
			}

			return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, $profile, $this );
		}
		return array();
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );;
	}

	function test_connection() {
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( ! Keyring_Util::is_error( $response ) ) {
			return true;
		}

		return $response;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Strava', 'init' ) );
