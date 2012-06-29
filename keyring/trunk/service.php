<?php
/**
 * A Service is a remote site/service/system for which Keyring is capable of managing
 * authentication. Each Service should have a series of methods for handling the creation
 * of an authentication token, verifying the token and for performing authenticated
 * requests.
 * 
 * @package Keyring
 */
abstract class Keyring_Service {
	const NAME          = '';
	const LABEL         = '';
	protected $token          = false;
	protected $requires_token = true;
	protected $store          = false;
	
	/**
	 * Handle the first part of getting a Token for this Service. In some cases
	 * this may involve UI, in others it might just be a redirect.
	 */
	abstract function request_token();
	
	/**
	 * Second step/verification of a Token. This is where you can make a
	 * test request, load meta, whatever you need to do. MUST include a call
	 * to ::verified() at the end, if the Token is successfully verified.
	 *
	 * @return void
	 * @author Beau Lebens
	 */
	abstract function verify_token();
	
	/**
	 * Make an outbound request against this Service, using the current Token
	 * if ->requires_token() return true.
	 *
	 * @param string $url The URL to make the request against
	 * @param array $params Additional parameters for the request (a la WP_HTTP)
	 * @return String containing the body of the response on success, or Keyring_Error on any non-200 response
	 */
	abstract function request( $url, array $params );
	
	/**
	 * Get a displayable string for the passed token, for this service
	 *
	 * @param obj $token Keyring_Token object
	 * @return String for display, describing $token
	 */
	abstract function get_display( Keyring_Token $token );
	
	/**
	 * Get an array of meta data to store with this token,
	 *
	 * @param Mixed $token 
	 * @return Array containing keyed values to store along with this token
	 */
	function build_token_meta( $token ) {
		return array();
	}
	
	function __construct() {
		$this->store = Keyring::get_token_store();
		
		// Default methods for handling actions, should always be defined (thus abstract, see above)
		add_action( 'keyring_' . $this->get_name() . '_request', array( $this, 'request_token' ) );
		add_action( 'keyring_' . $this->get_name() . '_verify', array( $this, 'verify_token' ) );
	}
	
	static function &init() {
		static $instance = false;
		
		if ( !$instance ) {
			$class = get_called_class();
			$services = Keyring::get_registered_services();
			if ( in_array( $class::NAME, array_keys( $services ) ) ) {
				$instance = $services[ $class::NAME ];
			} else {
				$instance = new $class;
				Keyring::register_service( $instance );
			}
		}
		
		return $instance;
	}
	
	/**
	 * Get/set whether this Service requires a token before making requests.
	 *
	 * @param boolean $does_it 
	 * @return True if token is required, false if not. If called with no
	 *         param, then just returns true/false. If called with a bool,
	 *         then set requirement to true/false as specified.
	 */
	function requires_token( $does_it = null ) {
		if ( is_null( $does_it ) )
			return $this->requires_token;
		
		$requires = $this->requires_token;
		$this->requires_token = $does_it;
		return $requires;
	}
	
	function get_name() {
		$c = get_called_class();
		if ( '' != $c::NAME )
			$name = $c::NAME;
		else
			$name = strtolower( $c );
		return $name;
	}
	
	function get_label() {
		$c = get_called_class();
		if ( '' != $c::LABEL )
			$label = $c::LABEL;
		else
			$label = $this->get_name();
		return $label;
	}
	
	function set_endpoint( $type, $url, $method = 'GET' ) {
		$this->{$type . '_url'}    = $url;
		$this->{$type . '_method'} = strtoupper( $method );
		return true;
	}
	
	function basic_ui() {
		if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-manage-' . $this->get_name() ) )
			wp_die( __( 'Invalid/missing management nonce.', 'keyring' ) );
		
		// Common Header
		echo '<div class="wrap">';
		screen_icon( 'ms-admin' );
		echo '<h2>' . __( 'Keyring Service Management', 'keyring' ) . '</h2>';
		echo '<p><a href="' . Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) . '">' . __( '&larr; Back', 'keyring' ) . '</a></p>';
		echo '<h3>' . sprintf( __( '%s API Credentials', 'keyring' ), esc_html( $this->get_label() ) ) . '</h3>';
		
		// Handle actually saving credentials
		if ( isset( $_POST['api_key'] ) && isset( $_POST['api_secret'] ) ) {
			// Store credentials against this service
			$this->update_credentials( array(
				'key' => stripslashes( $_POST['api_key'] ),
				'secret' => stripslashes( $_POST['api_secret'] )
			) );
			echo '<div class="updated"><p>' . __( 'Credentials saved.', 'keyring' ) . '</p></div>';
		}
		
		$api_key = $api_secret = '';
		if ( $creds = $this->get_credentials() ) {
			$api_key = $creds['key'];
			$api_secret = $creds['secret'];
		}
		
		echo apply_filters( 'keyring_' . $this->get_name() . '_basic_ui_intro', '' );
		
		// Output basic form for collecting key/secret
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="manage" />';
		wp_nonce_field( 'keyring-manage', 'kr_nonce', false );
		wp_nonce_field( 'keyring-manage-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'API Key', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="api_key" value="' . esc_attr( $api_key ) . '" id="api_key" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'API Secret', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="api_secret" value="' . esc_attr( $api_secret ) . '" id="api_secret" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Save Changes', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url() ) . '" class="submitdelete" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
	}
	
	/**
	 * Return any stored credentials for this service, or false if none.
	 *
	 * @return Array containing credentials or false if none
	 */
	function get_credentials() {
		$all = get_option( 'keyring_credentials' );
		if ( !empty( $all[ $this->get_name() ] ) )
			return $all[ $this->get_name() ];
		return false;
	}
	
	/**
	 * Update stored credentials for this service. Accept an array and just
	 * store it in a serialized array, keyed off the name of the service.
	 *
	 * @param array $credentials 
	 */
	function update_credentials( array $credentials ) {
		$all = get_option( 'keyring_credentials' );
		$all[ $this->get_name() ] = $credentials;
		return update_option( 'keyring_credentials', $all );
	}
	
	function verified( $id ) {
		$c = get_called_class();
		
		// If something else needs to be done, do it
		do_action( 'keyring_connection_verified', $c::NAME, $id );
		
		// Back to Keyring admin, with ?service=SERVICE&created=UNIQUE_ID&kr_nonce=NONCE
		$kr_nonce = wp_create_nonce( 'keyring-created' );
		$url = apply_filters( 'keyring_verified_redirect', Keyring_Util::admin_url( $c::NAME, array( 'action' => 'created', 'id' => $id, 'kr_nonce' => $kr_nonce ) ), $c::NAME );
		Keyring_Util::debug( $url );
		wp_safe_redirect( $url );
		exit;
	}
	
	function is_connected() {
		$c = get_called_class();
		$store = Keyring::get_token_store();
		return $store->count( $c::NAME );
	}
	
	function store_token( $token, $meta ) {
		$meta['_classname'] = get_called_class();
		$id = $this->store->insert( $this->get_name(), $token, $meta );
		if ( !$id ) {
			return $id;
		}

		$get_token = $this->store->get_token( $this->get_name(), $id, $meta );
		if ( $get_token ) {
			$this->set_token( $get_token );
		}

		return $id;
	}
	
	function set_token( Keyring_Token $token ) {
		$this->token = $token;
	}
	
	function get_tokens( $id = false ) {
		$c = get_called_class();
		return $this->store->get_tokens( $c::NAME );
	}
	
	function token_select_box( $name, $create = false ) {
		$tokens = $this->get_tokens();
		return Keyring_Util::token_select_box( $tokens, $name, $create );
	}
}

// Load all packaged services in the ./includes/services/ directory by including all PHP files, first in core, then in extended
// Remove a Service (prevent it from loading at all) by filtering on 'keyring_services'
$keyring_services = glob( dirname( __FILE__ ) . "/includes/services/core/*.php" );
$keyring_services = array_merge( $keyring_services, glob( dirname( __FILE__ ) . "/includes/services/extended/*.php" ) );
$keyring_services = apply_filters( 'keyring_services', $keyring_services );
foreach ( $keyring_services as $keyring_service )
	require $keyring_service;
unset( $keyring_services, $keyring_service );
