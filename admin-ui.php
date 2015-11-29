<?php

/**
 * Provides the core admin UI (Tools > Keyring) which includes:
 *  - managing Service credentials
 *  - creating connections
 *  - deleting connections
 *  - (coming soon) managing active/inactive Services
 *
 * Run Keyring with KEYRING__HEADLESS_MODE defined as true to disable all UI.
 *
 * @package Keyring
 */
class Keyring_Admin_UI {
	var $keyring = false;

	function __construct() {
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
	}

	static function &init() {
		static $instance = false;

		if ( !$instance ) {
			$instance = new Keyring_Admin_UI;
		}

		return $instance;
	}

	function inline_css() {
		?><style type="text/css">
		.wrap ul li {
			list-style-type: square;
			margin: .3em 0 .3em 2em;
		}
		</style><?php
	}

	function admin_menu() {
		$hook = add_management_page( 'Keyring', 'Keyring', 'read', 'keyring', array( $this, 'admin_page' ), '' );
		add_action( "load-$hook", array( $this, 'admin_page_load' ) );
	}

	function admin_page_load() {
		$this->keyring = Keyring::init();
		add_action( 'admin_head', array( $this, 'inline_css' ) );
	}

	function admin_page_header( $screen = false ) {
		// Output the actual heading + icon for the page
		echo '<div class="wrap">';
		screen_icon( 'ms-admin' );
		switch ( $screen ) {
		case 'tokens' :
			echo '<h2>' . __( 'Keyring: Service Connections', 'keyring' ) . ' <a href="' . Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) . '" class="add-new-h2">' . __( 'Add New', 'keyring' ) . '</a></h2>';
			break;
		case 'services' :
			echo '<h2>' . __( 'Add New Connection', 'keyring' ) . '</h2>';
			echo '<p><a href="' . Keyring_Util::admin_url() . '">' . __( '&larr; Back', 'keyring' ) . '</a></p>';
			break;
		case 'error' :
			echo '<h2>' . __( 'Keyring Error!', 'keyring' ) . '</h2>';
			break;
		default :
			echo '<h2>' . __( 'Keyring', 'keyring' ) . '</h2>';
		}

		// Output any errors if we have them, then stop, and link back to home.
		if ( $this->keyring->has_errors() ) {
			echo '<div id="keyring-admin-errors" class="error"><ul>';
			foreach ( $this->keyring->get_errors() as $error ) {
				echo "<li>" . esc_html( $error ) . "</li>";
			}
			echo '</ul></div>';
			return;
		}

		// Output any messages as part of the UI (don't abort).
		if ( $this->keyring->has_messages() ) {
			echo '<div id="keyring-admin-messages" class="updated"><ul>';
			foreach ( $this->keyring->get_messages() as $message ) {
				echo "<li>" . esc_html( $message ) . "</li>";
			}
			echo '</ul></div>';
		}
	}

	static function admin_page_footer() {
		echo '</div>'; // class="wrap"
	}

	function admin_page() {
		// Handle delete request. Will default back to "tokens" later
		if ( isset( $_REQUEST['action'] ) && 'delete' == $_REQUEST['action'] ) {
			if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-delete-' . $_REQUEST['service'] . '-' . $_REQUEST['token'] ) ) {
				Keyring::error( __( 'Invalid/missing delete nonce.', 'keyring' ) );
				exit;
			}

			if ( $this->keyring->get_token_store()->delete( array( 'id' => (int) $_REQUEST['token'], 'type' => 'access' ) ) )
				Keyring::message( __( 'That connection has been deleted.', 'keyring' ) );
			else
				Keyring::message( __( 'Could not delete that connection!', 'keyring' ) );
		}

		// Handle test request. Will default back to "tokens" later
		if ( isset( $_REQUEST['action'] ) && 'test' == $_REQUEST['action'] ) {
			if ( !isset( $_REQUEST['nonce'] ) || !wp_verify_nonce( $_REQUEST['nonce'], 'keyring-test-' . $_REQUEST['service'] . '-' . $_REQUEST['token'] ) ) {
				Keyring::error( __( 'Invalid/missing testing nonce.', 'keyring' ) );
				exit;
			}

			// If the test_connection() method exists, call it for this service/connection
			$service = $this->keyring->get_service_by_name( $_REQUEST['service'] );
			if ( method_exists( $service, 'test_connection' ) ) {
				$service->set_token( $this->keyring->get_token_store()->get_token( array( 'id' => $_REQUEST['token'], 'type' => 'request' ) ) );

				$test = $service->test_connection();
				if ( true === $test ) {
					Keyring::message( __( 'This connection appears to be working.', 'keyring' ) );
				} else {
					Keyring::error( __( 'This connection is NOT working correctly.', 'keyring' ), $test, false );
				}
			} else {
				Keyring::message( __( 'This service does not currently support connection testing.', 'keyring' ) );
			}

		}

		// Set up our defaults
		$service = '';
		if ( !empty( $_REQUEST['service'] ) )
			$service = $_REQUEST['service'];

		$action = 'tokens';
		if ( isset( $_REQUEST['action'] ) && in_array( $_REQUEST['action'], array( 'tokens', 'services', 'request', 'verify', 'manage' ) ) )
			$action = $_REQUEST['action'];

		// Custom UI optionally hooked in to handle this service/action. Trigger action
		// and assume it handles everything, so bail out after that.
		if ( Keyring_Util::has_custom_ui( $service, $action ) ) {
			do_action( "keyring_{$service}_{$action}_ui" );
			return;
		}

		// Nothing else has bailed, so it must be one of our default/core screens.
		switch ( $action ) {
		case 'tokens' :
			$this->admin_page_header( 'tokens' );

			$list_table = new Keyring_Connections_List_Table();
			$list_table->display();

			$this->admin_page_footer();
			break;

		case 'services' :
			$this->admin_page_header( 'services' );

			$services = $this->keyring->get_registered_services();
			if ( count( $services ) ) {
				$configured = $not_configured = array();
				foreach ( $services as $service ) {
					if ( $service->is_configured() )
						$configured[] = $service;
					else
						$not_configured[] = $service;
				}

				if ( count( $configured ) ) {
					echo '<p><strong>' . __( 'Click a service to create a new connection:', 'keyring' ) . '</strong></p>';
					echo '<ul>';
					foreach ( $configured as $service ) {
						$request_kr_nonce = wp_create_nonce( 'keyring-request' );
						$request_nonce = wp_create_nonce( 'keyring-request-' . $service->get_name() );
						echo '<li><a href="' . esc_url( Keyring_Util::admin_url( $service->get_name(), array( 'action' => 'request', 'kr_nonce' => $request_kr_nonce, 'nonce' => $request_nonce ) ) ) . '">' . esc_html( $service->get_label() ) . '</a>';

						if ( has_action( 'keyring_' . $service->get_name() . '_manage_ui' ) ) {
							$manage_kr_nonce = wp_create_nonce( 'keyring-manage' );
							$manage_nonce = wp_create_nonce( 'keyring-manage-' . $service->get_name() );
							echo ' (<a href="' . esc_url( Keyring_Util::admin_url( $service->get_name(), array( 'action' => 'manage', 'kr_nonce' => $manage_kr_nonce, 'nonce' => $manage_nonce ) ) ) . '">' . esc_html( __( 'Manage', 'keyring' ) ) . '</a>)';
						}

						echo '</li>';
					}
					echo '</ul><br /><br />';
				} else {
					echo '<p>' . __( 'There are no fully-configured services available to connect to.', 'keyring' ) . '</p>';
				}

				if ( count( $not_configured ) ) {
					echo '<p>' . __( 'The following services need to be configured correctly before you can connect to them.', 'keyring' ) . '</p>';
					echo '<ul>';
					foreach ( $not_configured as $service ) {
						if ( !has_action( 'keyring_' . $service->get_name() . '_manage_ui' ) )
							continue;

						$manage_kr_nonce = wp_create_nonce( 'keyring-manage' );
						$manage_nonce = wp_create_nonce( 'keyring-manage-' . $service->get_name() );
						echo '<li><a href="' . esc_url( Keyring_Util::admin_url( $service->get_name(), array( 'action' => 'manage', 'kr_nonce' => $manage_kr_nonce, 'nonce' => $manage_nonce ) ) ) . '">' . esc_html( $service->get_label() ) . '</a></li>';
					}
					echo '</ul>';
				}
			}

			$this->admin_page_footer();
			break;
		}
	}
}

/** WordPress List Table Administration API and base class */
require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';

class Keyring_Connections_List_Table extends WP_List_Table {
	var $keyring = false;
	function __construct() {
		$this->keyring = Keyring::init();

		parent::__construct( array(
			'singular' => 'connection',
			'plural'   => 'connections',
			'screen'   => $this->keyring->admin_page,
		) );

		$this->items = Keyring::get_token_store()->get_tokens();
	}

	function no_items() {
		echo '<p>' . sprintf( __( 'You haven\'t added any connections yet. <a href="%s">Add a New Connection</a>.', 'keyring' ), esc_url( Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) ) ) . '</p>';
	}

	function get_columns() {
		return array(
			'service'  => __( 'Service', 'keyring' ),
			'avatar'   => __( 'Avatar', 'keyring' ),
			'id'       => __( 'External ID', 'keyring' ),
			'name'     => __( 'Name', 'keyring' ),
			'meta'     => __( 'Meta', 'keyring' ),
			'actions'  => '&nbsp;'
		);
	}

	function column_service( $row ) {
		echo $row->get_service()->get_label();
	}

	function column_avatar( $row ) {
		$picture = $row->get_meta( 'picture' );
		if ( $picture ) {
			echo '<img src="' . esc_attr( $picture ) . '" width="80" height="80" border="1" alt="' . __( 'Avatar', 'keyring' ) . '" />';
		} else {
			echo '-';
		}
	}

	function column_id( $row ) {
		echo $row->get_meta( 'user_id' );
	}

	function column_name( $row ) {
		// Make a few attempts to get something to display here
		$name = $row->get_meta( 'name' );
		if ( !$name )
			$name = $row->get_meta( 'username' );
		if ( !$name )
			$name = trim( $row->get_meta( 'first_name' ) . ' ' . $row->get_meta( 'last_name' ) );

		if ( $name )
			echo $name;
		else
			echo '-';
	}

	function column_meta( $row ) {
		echo '<a onclick="jQuery(this).siblings().slideToggle();" style="cursor:pointer;">Show</a>';
		echo '<div class="keyring-meta" style="display:none;">';
		foreach( $row->get_meta() as $key => $val ) {
			echo '<strong>' . $key . '</strong>: ' . $val . '<br />';
		}
		echo '</div>';
	}

	function column_actions( $row ) {
		$kr_delete_nonce = wp_create_nonce( 'keyring-delete' );
		$delete_nonce = wp_create_nonce( 'keyring-delete-' . $row->get_service()->get_name() . '-' . $row->get_uniq_id() );

		$kr_test_nonce = wp_create_nonce( 'keyring-test' );
		$test_nonce = wp_create_nonce( 'keyring-test-' . $row->get_service()->get_name() . '-' . $row->get_uniq_id() );

		echo '<span class="row-actions">';
		echo '<span class="trash"><a href="' . Keyring_Util::admin_url( false, array( 'action' => 'delete', 'service' => $row->get_service()->get_name(), 'token' => $row->get_uniq_id(), 'kr_nonce' => $kr_delete_nonce, 'nonce' => $delete_nonce ) ) . '" title="' . esc_attr( __( 'Delete', 'keyring' ) ) . '" class="delete">Delete</a></span>';
		echo ' | ';
		echo '<a href="' . Keyring_Util::admin_url( false, array( 'action' => 'test', 'service' => $row->get_service()->get_name(), 'token' => $row->get_uniq_id(), 'kr_nonce' => $kr_test_nonce, 'nonce' => $test_nonce ) ) . '" title="' . esc_attr( __( 'Test', 'keyring' ) ) . '" class="test">Test</a>';
		echo '</span>';
	}
}
