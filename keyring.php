<?php
/*
Plugin Name: Keyring
Plugin URI: https://beaulebens.com/projects/wp-keyring/
Description: Keyring helps you manage your keys. It provides a generic, very hookable framework for connecting to remote systems and managing your access tokens, username/password combos etc for those services. On its own it doesn't do much, but it enables other plugins to do things that require authorization to act on your behalf.
Version: 3.0
Author: Beau Lebens
Author URI: http://dentedreality.com.au
License: GPL v2 or newer <https://www.gnu.org/licenses/gpl.txt>
*/

// Define this in your wp-config (and set to true) to enable debugging
defined( 'KEYRING__DEBUG_MODE' ) or define( 'KEYRING__DEBUG_MODE', false );

// The name of a class which extends Keyring_Store to handle storage/manipulation of tokens.
// Optionally define this in your wp-config.php or some other global config file.
defined( 'KEYRING__TOKEN_STORE' ) or define( 'KEYRING__TOKEN_STORE', 'Keyring_SingleStore' );

// Keyring can be run in "headless" mode, which just avoids creating any UI, and leaves
// that up to you. Defaults to off (provides its own basic UI).
defined( 'KEYRING__HEADLESS_MODE' ) or define( 'KEYRING__HEADLESS_MODE', false );

// Debug/messaging levels. Don't mess with these
define( 'KEYRING__DEBUG_NOTICE', 1 );
define( 'KEYRING__DEBUG_WARN', 2 );
define( 'KEYRING__DEBUG_ERROR', 3 );

// Indicates Keyring is installed/active so that other plugins can detect it
define( 'KEYRING__VERSION', '3.0' );

/**
 * Core Keyring class that handles UI and the general flow of requesting access tokens etc
 * to manage access to remote services.
 *
 * @package Keyring
 */
class Keyring {
	protected $registered_services = array();
	protected $store               = false;
	protected $errors              = array();
	protected $messages            = array();
	protected $token_store         = '';
	public $admin_page             = 'keyring';

	public function __construct() {
		if ( ! KEYRING__HEADLESS_MODE ) {
			require_once __DIR__ . '/admin-ui.php';
			Keyring_Admin_UI::init();

			add_filter(
				'keyring_admin_url',
				function ( $url, $params ) {
					$url = admin_url( 'tools.php?page=' . Keyring::init()->admin_page );
					return add_query_arg( $params, $url );
				},
				10,
				2
			);
		}

		// This is used internally to create URLs, and also to know when to
		// attach handers. @see admin_url() and request_handlers()
		$this->admin_page = apply_filters( 'keyring_admin_page', 'keyring' );
	}

	public static function init( $force_load = false ) {
		static $instance = false;

		if ( ! $instance ) {
			if ( ! KEYRING__HEADLESS_MODE ) {
				load_plugin_textdomain( 'keyring', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
			}
			$instance = new Keyring();

			// Keyring is being loaded 'late', so we need to do some extra set-up
			if ( did_action( 'init' ) || $force_load ) {
				$instance->plugins_loaded();
				do_action( 'keyring_load_services' );
			}
		} else {
			if ( $force_load ) {
				$instance->plugins_loaded();
				do_action( 'keyring_load_services' );
			}
		}

		return $instance;
	}

	public static function plugins_loaded() {
		// Load stores early so we can confirm they're loaded correctly
		require_once __DIR__ . '/store.php';
		do_action( 'keyring_load_token_stores' );
		$keyring              = Keyring::init();
		$keyring->token_store = apply_filters( 'keyring_token_store', defined( 'KEYRING__TOKEN_STORE' ) ? KEYRING__TOKEN_STORE : false );
		if ( ! class_exists( $keyring->token_store ) || ! in_array( 'Keyring_Store', class_parents( $keyring->token_store ), true ) ) {
			/* translators: file name */
			wp_die( sprintf( __( 'Invalid <code>KEYRING__TOKEN_STORE</code> specified. Please make sure <code>KEYRING__TOKEN_STORE</code> is set to a valid classname for handling token storage in <code>%s</code> (or <code>wp-config.php</code>)', 'keyring' ), __FILE__ ) );
		}

		// Load base token and service definitions + core services
		require_once __DIR__ . '/token.php';
		require_once __DIR__ . '/service.php'; // Triggers a load of all core + extended service definitions

		// Initiate Keyring
		add_action( 'init', array( 'Keyring', 'init' ), 1 );

		// Load external Services (plugins etc should hook to this to define new ones/extensions)
		add_action(
			'init',
			function () {
				do_action( 'keyring_load_services' );
			},
			2
		);

		/**
		 * And trigger request handlers, which plugins and extended Services use to handle UI,
		 * redirects, errors etc.
		 * @see ::request_handlers()
		 */
		add_action( 'admin_init', array( 'Keyring', 'request_handlers' ), 100 );
	}

	/**
	 * Core request handler which is the crux of everything. An action is called
	 * here for almost everything Keyring does, so you can use it to intercept
	 * almost everything. Based entirely on $_REQUEST[page|action|service]
	 */
	public static function request_handlers() {
		global $current_user;
		Keyring_Util::debug( 'request_handers' );

		$_REQUEST = Keyring_Util::cleanup_request_parameters( $_REQUEST );
		Keyring_Util::debug( $_REQUEST );

		if ( ! empty( $_REQUEST['state'] ) ) {
			Keyring_Util::unpack_state_parameters( $_REQUEST['state'] );
		}

		if ( defined( 'KEYRING__FORCE_USER' ) && KEYRING__FORCE_USER && in_array( $_REQUEST['action'], array( 'request', 'verify' ), true ) ) {
			global $current_user;
			$real_user = $current_user->ID;
			wp_set_current_user( KEYRING__FORCE_USER );
		}

		if (
				! empty( $_REQUEST['action'] )
			&&
				in_array( $_REQUEST['action'], apply_filters( 'keyring_core_actions', array( 'request', 'verify', 'created', 'delete', 'manage' ) ), true )
			&&
				! empty( $_REQUEST['service'] )
			&&
				in_array( $_REQUEST['service'], array_keys( Keyring::get_registered_services() ), true )
		) {
			// We have an action here to allow us to do things pre-authorization, just in case
			Keyring_Util::debug( "pre_keyring_{$_REQUEST['service']}_{$_REQUEST['action']}", $_REQUEST );
			do_action( "pre_keyring_{$_REQUEST['service']}_{$_REQUEST['action']}", $_REQUEST );

			// Core nonce check required for everything. "keyring-ACTION" is the kr_nonce format
			if ( ! isset( $_REQUEST['kr_nonce'] ) || ! wp_verify_nonce( $_REQUEST['kr_nonce'], 'keyring-' . $_REQUEST['action'] ) ) {
				Keyring::error( __( 'Invalid/missing Keyring core nonce. All core actions require a valid nonce.', 'keyring' ) );
				exit;
			}

			Keyring_Util::debug( "keyring_{$_REQUEST['service']}_{$_REQUEST['action']}" );
			Keyring_Util::debug( $_GET );
			do_action( "keyring_{$_REQUEST['service']}_{$_REQUEST['action']}", $_REQUEST );

			if ( 'delete' === $_REQUEST['action'] ) {
				do_action( 'keyring_connection_deleted', $_REQUEST['service'], $_REQUEST );
			}
		}

		if ( defined( 'KEYRING__FORCE_USER' ) && KEYRING__FORCE_USER && in_array( $_REQUEST['action'], array( 'request', 'verify' ), true ) ) {
			wp_set_current_user( $real_user );
		}
	}

	public static function register_service( Keyring_Service $service ) {
		Keyring::init()->registered_services[ $service->get_name() ] = $service;
		return true;
	}

	public static function get_registered_services() {
		return Keyring::init()->registered_services;
	}

	public static function get_service_by_name( $name ) {
		$keyring = Keyring::init();
		if ( ! isset( $keyring->registered_services[ $name ] ) ) {
			return null;
		}

		return $keyring->registered_services[ $name ];
	}

	public static function get_token_store() {
		$keyring = Keyring::init();

		if ( ! $keyring->store ) {
			$keyring->store = call_user_func( array( $keyring->token_store, 'init' ) );
		}

		return $keyring->store;
	}

	public static function message( $str ) {
		$keyring             = Keyring::init();
		$keyring->messages[] = $str;
	}

	/**
	 * Generic error handler/trigger.
	 * @param  String $str  Informational message (user-readable)
	 * @param  array  $info Additional information relating to the error.
	 * @param  boolean $should_die If we should immediately die (default) or continue
	 */
	public static function error( $str, $info = array(), $should_die = true ) {
		$keyring           = Keyring::init();
		$keyring->errors[] = $str;
		do_action( 'keyring_error', $str, $info );
		if ( $should_die ) {
			wp_die( $str, __( 'Keyring Error', 'keyring' ) );
			exit;
		}
	}

	public function has_errors() {
		return count( $this->errors );
	}

	public function has_messages() {
		return count( $this->messages );
	}

	public function get_messages() {
		return $this->messages;
	}

	public function get_errors() {
		return $this->errors;
	}
}

require_once __DIR__ . '/keyring-util.php';
require_once __DIR__ . '/keyring-error.php';

// This is the main hook that kicks off everything. Needs to be early so we have time to load everything.
add_action( 'plugins_loaded', array( 'Keyring', 'plugins_loaded' ) );
