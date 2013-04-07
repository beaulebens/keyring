<?php
/*
Plugin Name: Keyring
Plugin URI: http://dentedreality.com.au/projects/wp-keyring/
Description: Keyring helps you manage your keys. It provides a generic, very hookable framework for connecting to remote systems and managing your access tokens, username/password combos etc for those services. On its own it doesn't do much, but it enables other plugins to do things that require authorization to act on your behalf.
Version: 1.4
Author: Beau Lebens
Author URI: http://dentedreality.com.au
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
define( 'KEYRING__DEBUG_WARN',   2 );
define( 'KEYRING__DEBUG_ERROR',  3 );

// Indicates Keyring is installed/active so that other plugins can detect it
define( 'KEYRING__VERSION', 1.4 );

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
	var $admin_page                = 'keyring';

	function __construct() {
		if ( ! KEYRING__HEADLESS_MODE ) {
			require_once dirname( __FILE__ ) . '/admin-ui.php';
			Keyring_Admin_UI::init();

			add_filter( 'keyring_admin_url', function( $url ) {
				return admin_url( 'tools.php?page=' . Keyring::init()->admin_page );
			} );
		}

		// This is used internally to create URLs, and also to know when to
		// attach handers. @see admin_url() and request_handlers()
		$this->admin_page = apply_filters( 'keyring_admin_page', 'keyring' );
	}

	static function &init( $force_load = false ) {
		static $instance = false;

		if ( !$instance ) {
			if ( ! KEYRING__HEADLESS_MODE )
				load_plugin_textdomain( 'keyring', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
			$instance = new Keyring;

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

	function plugins_loaded() {
		// Load stores early so we can confirm they're loaded correctly
		require_once dirname( __FILE__ ) . '/store.php';
		do_action( 'keyring_load_token_stores' );
		if ( !defined( 'KEYRING__TOKEN_STORE' ) || !class_exists( KEYRING__TOKEN_STORE ) || !in_array( 'Keyring_Store', class_parents( KEYRING__TOKEN_STORE ) ) )
			wp_die( sprintf( __( 'Invalid <code>KEYRING__TOKEN_STORE</code> specified. Please make sure <code>KEYRING__TOKEN_STORE</code> is set to a valid classname for handling token storage in <code>%s</code> (or <code>wp-config.php</code>)', 'keyring' ), __FILE__ ) );

		// Load base token and service definitions + core services
		require_once dirname( __FILE__ ) . '/token.php';
		require_once dirname( __FILE__ ) . '/service.php'; // Triggers a load of all core + extended service definitions

		// Initiate Keyring
		add_action( 'init', array( 'Keyring', 'init' ), 1 );

		// Load external Services (plugins etc should hook to this to define new ones/extensions)
		add_action( 'init', function() {
			do_action( 'keyring_load_services' );
		}, 2 );

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
	function request_handlers() {
		global $current_user;

		if ( defined( 'KEYRING__FORCE_USER' ) && KEYRING__FORCE_USER && in_array( $_REQUEST['action'], array( 'request', 'verify' ) ) ) {
			global $current_user;
			$real_user = $current_user->ID;
			wp_set_current_user( KEYRING__FORCE_USER );
		}

		if (
				!empty( $_REQUEST['action'] )
			&&
				in_array( $_REQUEST['action'], apply_filters( 'keyring_core_actions', array( 'request', 'verify', 'created', 'delete', 'manage' ) ) )
			&&
				!empty( $_REQUEST['service'] )
			&&
				in_array( $_REQUEST['service'], array_keys( Keyring::get_registered_services() ) )
		) {
			// We have an action here to allow us to do things pre-authorization, just in case
			do_action( "pre_keyring_{$_REQUEST['service']}_{$_REQUEST['action']}", $_REQUEST );

			// Core nonce check required for everything. "keyring-ACTION" is the kr_nonce format
			if ( !isset( $_REQUEST['kr_nonce'] ) || !wp_verify_nonce( $_REQUEST['kr_nonce'], 'keyring-' . $_REQUEST['action'] ) ) {
				Keyring::error( __( 'Invalid/missing Keyring core nonce. All core actions require a valid nonce.', 'keyring' ) );
				exit;
			}

			Keyring_Util::debug( "keyring_{$_REQUEST['service']}_{$_REQUEST['action']}" );
			Keyring_Util::debug( $_GET );
			do_action( "keyring_{$_REQUEST['service']}_{$_REQUEST['action']}", $_REQUEST );

			if ( 'delete' == $_REQUEST['action'] )
				do_action( "keyring_connection_deleted", $_REQUEST['service'], $_REQUEST );
		}

		if ( defined( 'KEYRING__FORCE_USER' ) && KEYRING__FORCE_USER && in_array( $_REQUEST['action'], array( 'request', 'verify' ) ) )
			wp_set_current_user( $real_user );
	}

	static function register_service( Keyring_Service $service ) {
		if ( Keyring_Util::is_service( $service ) ) {
			Keyring::init()->registered_services[ $service->get_name() ] = $service;
			return true;
		}
		return false;
	}

	static function get_registered_services() {
		return Keyring::init()->registered_services;
	}

	static function get_service_by_name( $name ) {
		$keyring = Keyring::init();
		if ( !isset( $keyring->registered_services[ $name ] ) )
			return null;

		return $keyring->registered_services[ $name ];
	}

	static function get_token_store() {
		$keyring = Keyring::init();

		if ( !$keyring->store )
			$keyring->store = call_user_func( array( KEYRING__TOKEN_STORE, 'init' ) );

		return $keyring->store;
	}

	static function message( $str ) {
		$keyring = Keyring::init();
		$keyring->messages[] = $str;
	}

	/**
	 * Generic error handler/trigger.
	 * @param  String $str	Informational message (user-readable)
	 * @param  array  $info Additional information relating to the error.
	 */
	static function error( $str, $info = array() ) {
		$keyring = Keyring::init();
		$keyring->errors[] = $str;
		do_action( 'keyring_error', $str, $info, isset( $this ) ? $this : null );
		wp_die( $str, __( 'Keyring Error', 'keyring' ) );
		exit;
	}

	function has_errors() {
		return count( $this->errors );
	}

	function has_messages() {
		return count( $this->messages );
	}

	function get_messages() {
		return $this->messages;
	}

	function get_errors() {
		return $this->errors;
	}
}

class Keyring_Util {
	static function debug( $str, $level = KEYRING__DEBUG_NOTICE ) {
		if ( !KEYRING__DEBUG_MODE )
			return;

		if ( is_object( $str ) || is_array( $str ) )
			$str = print_r( $str, true );

		switch ( $level ) {
		case KEYRING__DEBUG_WARN :
			echo "<div style='border:solid 1px #000; padding: 5px; background: #eee;'>Keyring Warning: $str</div>";
			break;
		case KEYRING__DEBUG_ERROR :
			wp_die( '<h1>Keyring Error:</h1>' . '<p>' . $str . '</p>' );
			exit;
		}

		error_log( "Keyring: $str" );
	}

	static function is_service( $service ) {
		if ( is_object( $service ) && is_subclass_of( $service, 'Keyring_Service' ) )
			return true;

		return false;
	}

	static function has_custom_ui( $service, $action ) {
		return has_action( "keyring_{$service}_{$action}_ui" );
	}

	/**
	 * Get a URL to the Keyring admin UI, works kinda like WP's admin_url()
	 *
	 * @param string $service Shortname of a specific service.
	 * @return URL to Keyring admin UI (main listing, or specific service verify process)
	 */
	static function admin_url( $service = false, $params = array() ) {
		$url = apply_filters( 'keyring_admin_url', admin_url( '' ) );

		if ( $service )
			$url = add_query_arg( array( 'service' => $service ), $url );

		if ( count( $params ) )
			$url = add_query_arg( $params, $url );

		return $url;
	}

	static function connect_to( $service, $for ) {
		Keyring_Util::debug( 'Connect to: ' . $service );
		// Redirect into Keyring's auth handler if a valid service is provided
		$kr_nonce = wp_create_nonce( 'keyring-request' );
		$request_nonce = wp_create_nonce( 'keyring-request-' . $service );
		wp_safe_redirect(
			Keyring_Util::admin_url(
				$service,
				array(
					'action'   => 'request',
					'kr_nonce' => $kr_nonce,
					'nonce'    => $request_nonce,
					'for'      => $for
				)
			)
		);
		exit;
	}

	static function token_select_box( $tokens, $name, $create = false ) {
		?><select name="<?php echo esc_attr( $name ); ?>" id="<?php echo esc_attr( $name ); ?>">
		<?php if ( $create ) : ?>
			<option value="new"><?php _e( 'Create a new connection&hellip;', 'keyring' ); ?></option>
		<?php endif; ?>
		<?php foreach ( (array) $tokens as $token ) : ?>
			<option value="<?php echo $token->get_uniq_id(); ?>"><?php echo $token->get_display(); ?></option>
		<?php endforeach; ?>
		</select><?php
	}

	static function is_error( $obj ) {
		return is_a( $obj, 'Keyring_Error' );
	}
}

/**
 * Stub implementation of an error object. May at some point get custom, but
 * treat it like a normal WP_Error for now.
 */
class Keyring_Error extends WP_Error { }

// This is the main hook that kicks off everything. Needs to be early so we have time to load everything.
add_action( 'plugins_loaded', array( 'Keyring', 'plugins_loaded' ) );
