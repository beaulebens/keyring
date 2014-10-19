<?php
/**
 * This Service is provided as an example only. It doesn't do anything useful :)
 */

// Always extend Keyring_Service, or something else which extends it (e.g. Keyring_Service_OAuth1)
class Keyring_Service_Example extends Keyring_Service {
	const NAME = 'example';
	const LABEL = 'Example Service';

	function __construct() {
		// If you need a custom __construct(), make sure to call the parent explicitly like this
		parent::__construct();

		// Optionally register methods (of this object) to handle the UI for different actions
		// action is in the format "keyring_{$service}_{request/verify}_ui".
		// These are optional, and are only required if you need the user to see/do something during
		// each step.
		add_action( 'keyring_example_request_ui', array( $this, 'request_ui' ) );
		add_action( 'keyring_example_verify_ui', array( $this, 'verify_ui' ) );

		// Enable "basic" UI for entering key/secret, which a lot of services require
		// add_action( 'keyring_example_manage_ui', array( $this, 'basic_ui' ) );

		// Optionally make this a service that we can communicate with *without*
		// requiring any sort of connection
		$this->requires_token( false );
	}

	/**
	 * Allows you to do things before any output has been sent to the browser.
	 * This means you can redirect to a remote site, another page etc if need be.
	 */
	function request_token() {
		// Nothing to do in this example
	}

	/**
	 * You can define how a token presents itself to the user here. For example for Twitter,
	 * we might show "@" . $screen_name.
	 *
	 * @param Keyring_Access_Token $token
	 * @return String for use in UIs etc that helps identify this specific token
	 */
	function get_display( Keyring_Access_Token $token ) {
		return $token->token;
	}

	/**
	 * See __construct() for details on how this is hooked in to handle the UI for
	 * during the request process.
	 */
	function request_ui() {
		Keyring::admin_page_header(); // Generic header which can be used (includes h2 header)
		echo '<p>This is just an example of how you could display some sort of custom UI if you needed to.</p>';
		echo '<p>Clicking the button below will generate a random token and store it as an example.</p>';
		echo '<p class="submitbox">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url( 'example', array( 'action' => 'verify' ) ) ) . '" class="button-primary">' . __( 'Continue', 'keyring' ) . '</a>';
		echo '<a href="' . esc_attr( $_SERVER['HTTP_REFERER'] ) . '" class="submitdelete" style="margin-left:2em;">Abort</a>';
		echo '</p>';
		Keyring::admin_page_footer();
	}

	/**
	 * Allows you to do things before any output has been sent to the browser.
	 * This means you can redirect to a remote site, another page etc if need be.
	 */
	function verify_token() {
		// Generate a fake token and store it for this example
		$token = sha1( time() . mt_rand( 0, 1000 ) . time() );
		$meta = array( 'time' => time(), 'user' => get_current_user() );
		$this->store_token( $token, $meta );
	}

	/**
	 * This method will be used to make requests against this service. This is where
	 * you should handle injecting tokens/headers/etc required for authentication.
	 *
	 * @param string $url
	 * @param array $params additional parameters/headers for the request. Passed to WP_Http
	 * @return Response body as a string, or a Keyring_Error with the full WP_Http response object as the "message"
	 */
	function request( $url, array $params = array() ) {
		// empty
	}

	/**
	 * See __construct() for details on how this is hooked in to handle the UI for
	 * during the verify process.
	 */
	function verify_ui() {
		Keyring::admin_page_header();
		echo '<p>As an example, we just randomly generated a token and saved it in the token store. When you go back to your Connections listing, you should see it listed there under "Example Service".</p>';
		echo '<p><a href="' . esc_url( Keyring_Util::admin_url() ) . '" class="button-primary">' . __( 'Done', 'keyring' ) . '</a>';
		Keyring::admin_page_footer();
	}
}

// Always hook into keyring_load_services and use your init method to initiate a Service properly (singleton)
add_action( 'keyring_load_services', array( 'Keyring_Service_Example', 'init' ) );
