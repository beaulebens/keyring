<?php
/**
 * A Service is a remote site/service/system for which Keyring is capable of managing
 * authentication. Each Service should have a series of methods for handling the creation
 * of an authentication token, verifying the token and for performing authenticated
 * requests.
 */
abstract class Keyring_Service {
	const NAME = '';
	const LABEL = '';
	
	abstract function request_token();
	abstract function verify_token();
	abstract function request( $token, $url, $params );
	abstract function get_display( $token );
	
	function __construct( $details = array() ) {
		$defaults = array(
			'name'  => false,
			'label' => false,
		);
		
		$details = wp_parse_args( $defaults, $details );
		
		if ( $details['label'] && !$this->label )
			$this->label = $details['label'];
		
		if ( $details['name'] && !$this->name )
			$this->name = $details['name'];
		
		// Default methods for handling actions, should always be defined (thus abstract, see above)
		add_action( 'keyring_' . $this->get_name() . '_request', array( $this, 'request_token' ) );
		add_action( 'keyring_' . $this->get_name() . '_verify', array( $this, 'verify_token' ) );
	}
	
	static function &init( $details = array() ) {
		static $instance = false;
		
		$class = get_called_class();
		if ( 'Keyring_Service' == $class || is_subclass_of( $class, 'Keyring_Service' ) ) {
			if ( !$instance ) {
				if ( !in_array( $class::NAME, Keyring::get_registered_services() ) ) {
					$instance = new $class( $details );
					Keyring::register_service( $instance );
				} else {
					$services = Keyring::get_registered_services();
					$instance = $services[ $class::NAME ];
				}
			}
			return $instance;
		}
		return false;
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
			$name = $c::LABEL;
		else
			$name = $this->get_name();
		return $name;
	}
	
	function set_endpoint( $type, $url, $method = 'GET' ) {
		$this->{$type . '_url'}    = $url;
		$this->{$type . '_method'} = strtoupper( $method );
		return true;
	}
	
	function basic_ui() {
		// Common Header
		echo '<div class="wrap">';
		screen_icon( 'ms-admin' );
		echo '<h2>' . __( 'Keyring Service Management', 'keyring' ) . '</h2>';
		echo '<p><a href="' . Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) . '">' . __( '&larr; Back', 'keyring' ) . '</a></p>';
		echo '<h3>' . sprintf( __( '%s API Credentials', 'keyring' ), esc_html( $this->get_label() ) ) . '</h3>';
		
		// Handle actually saving credentials
		if ( isset( $_POST['api_key'] ) && isset( $_POST['api_secret'] ) ) {
			// Store credentials against this service
			$this->update_credentials( array( 'key' => $_POST['api_key'], 'secret' => $_POST['api_secret'] ) );
			echo '<div class="updated"><p>' . __( 'Credentials saved.', 'keyring' ) . '</p></div>';
		}
		
		$api_key = $api_secret = '';
		if ( $creds = $this->get_credentials() ) {
			$api_key = $creds['key'];
			$api_secret = $creds['secret'];
		}
		
		// Output basic form for collecting key/secret
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="manage" />';
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
	function update_credentials( $credentials ) {
		$all = get_option( 'keyring_credentials' );
		$all[ $this->get_name() ] = $credentials;
		return update_option( 'keyring_credentials', $all );
	}
	
	function verified( $id ) {
		$c = get_called_class();
		$service = $c::NAME;
		// Back to Keyring admin, with ?service=SERVICE&created=UNIQUE_ID
		$url = Keyring_Util::admin_url( $c::NAME, array( 'action' => 'created', 'id' => $id ) );
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
		$store = Keyring::get_token_store();
		$meta['classname'] = get_called_class();
		return $store->insert( $this->get_name(), $token, $meta );
	}
	
	function get_tokens( $id = false ) {
		$c = get_called_class();
		return Keyring::get_tokens( $c::NAME, $id );
	}
	
	function token_select_box( $name, $create = false ) {
		$tokens = $this->get_tokens( false );
		return Keyring_Util::token_select_box( $tokens, $name, $create );
	}
}

// Load all packaged services in the ./services/ directory by including all PHP files, first in core, then in extended
$keyring_services = glob( dirname( __FILE__ ) . "/includes/services/core/*.php" );
$keyring_services = array_merge( $keyring_services, glob( dirname( __FILE__ ) . "/includes/services/extended/*.php" ) );
foreach ( $keyring_services as $service )
	require_once $service;
unset( $keyring_services );
