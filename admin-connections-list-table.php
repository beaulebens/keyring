<?php

/** WordPress List Table Administration API and base class */
require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';

class Keyring_Connections_List_Table extends WP_List_Table {
	public $keyring = false;
	public function __construct() {
		$this->keyring = Keyring::init();

		parent::__construct(
			array(
				'singular' => 'connection',
				'plural'   => 'connections',
				'screen'   => $this->keyring->admin_page,
			)
		);

		$this->items = Keyring::get_token_store()->get_tokens();
	}

	public function no_items() {
		/* translators: url */
		echo '<p>' . sprintf( __( 'You haven\'t added any connections yet. <a href="%s">Add a New Connection</a>.', 'keyring' ), esc_url( Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) ) ) . '</p>';
	}

	public function get_columns() {
		return array(
			'service' => __( 'Service', 'keyring' ),
			'avatar'  => __( 'Avatar', 'keyring' ),
			'id'      => __( 'External ID', 'keyring' ),
			'name'    => __( 'Name', 'keyring' ),
			'meta'    => __( 'Meta', 'keyring' ),
			'actions' => '&nbsp;',
		);
	}

	public function column_service( $row ) {
		echo $row->get_service()->get_label();
	}

	public function column_avatar( $row ) {
		$picture = set_url_scheme( $row->get_meta( 'picture' ) );
		if ( $picture ) {
			echo '<img src="' . esc_url( $picture ) . '" width="80" height="80" border="1" alt="' . __( 'Avatar', 'keyring' ) . '" />';
		} else {
			echo '-';
		}
	}

	public function column_id( $row ) {
		echo $row->get_meta( 'user_id' );
	}

	public function column_name( $row ) {
		// Make a few attempts to get something to display here
		$name = $row->get_meta( 'name' );
		if ( ! $name ) {
			$name = $row->get_meta( 'username' );
		}
		if ( ! $name ) {
			$name = trim( $row->get_meta( 'first_name' ) . ' ' . $row->get_meta( 'last_name' ) );
		}

		if ( $name ) {
			echo $name;
		} else {
			echo '-';
		}
	}

	public function column_meta( $row ) {
		echo '<a onclick="jQuery(this).siblings().slideToggle();" style="cursor:pointer;">Show</a>';
		echo '<div class="keyring-meta" style="display:none;">';
		foreach ( $row->get_meta() as $key => $val ) {
			echo '<strong>' . $key . '</strong>: ' . $val . '<br />';
		}
		echo '</div>';
	}

	public function column_actions( $row ) {
		$kr_delete_nonce = wp_create_nonce( 'keyring-delete' );
		$delete_nonce    = wp_create_nonce( 'keyring-delete-' . $row->get_service()->get_name() . '-' . $row->get_uniq_id() );

		$kr_test_nonce = wp_create_nonce( 'keyring-test' );
		$test_nonce    = wp_create_nonce( 'keyring-test-' . $row->get_service()->get_name() . '-' . $row->get_uniq_id() );

		echo '<span class="row-actions visible">';
		echo '<span class="trash"><a href="' . Keyring_Util::admin_url(
			false,
			array(
				'action'   => 'delete',
				'service'  => $row->get_service()->get_name(),
				'token'    => $row->get_uniq_id(),
				'kr_nonce' => $kr_delete_nonce,
				'nonce'    => $delete_nonce,
			)
		) . '" title="' . esc_attr( __( 'Delete', 'keyring' ) ) . '" class="delete">Delete</a></span>';
		echo ' | ';
		echo '<a href="' . Keyring_Util::admin_url(
			false,
			array(
				'action'   => 'test',
				'service'  => $row->get_service()->get_name(),
				'token'    => $row->get_uniq_id(),
				'kr_nonce' => $kr_test_nonce,
				'nonce'    => $test_nonce,
			)
		) . '" title="' . esc_attr( __( 'Test', 'keyring' ) ) . '" class="test">Test</a>';
		echo '</span>';
	}
}
