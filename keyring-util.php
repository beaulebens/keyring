<?php

class Keyring_Util {
	public static function debug( $str, $level = KEYRING__DEBUG_NOTICE ) {
		if ( ! KEYRING__DEBUG_MODE ) {
			return;
		}

		if ( is_object( $str ) || is_array( $str ) ) {
			$str = print_r( $str, true );
		}

		switch ( $level ) {
			case KEYRING__DEBUG_WARN:
				echo "<div style='border:solid 1px #000; padding: 5px; background: #eee;'>Keyring Warning: $str</div>";
				break;
			case KEYRING__DEBUG_ERROR:
				wp_die( '<h1>Keyring Error:</h1>' . '<p>' . $str . '</p>' );
				exit;
		}

		error_log( "Keyring: $str" );
	}

	/**
	 * @deprecated No longer used internally.
	 * @return boolean
	 */
	public static function is_service( $service ) {
		if ( is_object( $service ) && is_subclass_of( $service, 'Keyring_Service' ) ) {
			return true;
		}

		return false;
	}

	public static function has_custom_ui( $service, $action ) {
		return has_action( "keyring_{$service}_{$action}_ui" );
	}

	/**
	 * Get a URL to the Keyring admin UI, works kinda like WP's admin_url()
	 *
	 * @param string $service Shortname of a specific service.
	 * @return URL to Keyring admin UI (main listing, or specific service verify process)
	 */
	public static function admin_url( $service = false, $params = array() ) {
		$url = admin_url();

		if ( $service ) {
			$params['service'] = $service;
		}

		if ( count( $params ) ) {
			$url = add_query_arg( $params, $url );
		}

		return apply_filters( 'keyring_admin_url', $url, $params );
	}

	public static function connect_to( $service, $context ) {
		Keyring_Util::debug( 'Connect to: ' . $service );
		// Redirect into Keyring's auth handler if a valid service is provided
		$kr_nonce      = wp_create_nonce( 'keyring-request' );
		$request_nonce = wp_create_nonce( 'keyring-request-' . $service );
		wp_safe_redirect(
			Keyring_Util::admin_url(
				$service,
				array(
					'action'   => 'request',
					'kr_nonce' => $kr_nonce,
					'nonce'    => $request_nonce,
					'for'      => $context,
				)
			)
		);
		exit;
	}

	public static function token_select_box( $tokens, $name, $create = false ) {
		?><select name="<?php echo esc_attr( $name ); ?>" id="<?php echo esc_attr( $name ); ?>">
		<?php if ( $create ) : ?>
			<option value="new"><?php _e( 'Create a new connection&hellip;', 'keyring' ); ?></option>
		<?php endif; ?>
		<?php foreach ( (array) $tokens as $token ) : ?>
			<option value="<?php echo $token->get_uniq_id(); ?>"><?php echo $token->get_display(); ?></option>
		<?php endforeach; ?>
		</select>
		<?php
	}

	public static function is_error( $obj ) {
		return is_a( $obj, 'Keyring_Error' );
	}

	/**
	 * For some services the request params are JSON encoded into the state param. This
	 * method JSON decodes these and adds them back to the _REQUEST global
	 *
	 * @param string $state The JSON encoded $_REQUEST['state'] param
	 * @return void
	 */
	public static function unpack_state_parameters( $state ) {
		$unpacked_state = json_decode( base64_decode( $state ), true );
		if ( ! empty( $unpacked_state['hash'] ) ) {
			$validated_parameters = Keyring_Util::get_validated_parameters( $unpacked_state );

			if ( ! $validated_parameters ) {
				Keyring::error( __( 'Invalid data returned by the service. Please try again.', 'keyring' ) );
				exit;
			}

			foreach ( $validated_parameters as $key => $value ) {
				$_REQUEST[ $key ] = $value;
			}

			$_GET['state'] = $validated_parameters['state'];
		}
	}

	/**
	 * Get an sha256 hash of a JSON encoded array of parameters
	 *
	 * @param string $encoded_parameters A JSON encoded string of a parameter array.
	 * @return string An sha256 hash
	 */
	public static function get_parameter_hash( $encoded_parameters ) {
		return hash_hmac( 'sha256', $encoded_parameters, NONCE_KEY );
	}

	/**
	 * Get a based 64 and JSON encoded representation of an array of parameters which includes
	 * a hash of the original params so they can be verified in a service callback
	 *
	 * @param array $parameters An array of query parameters.
	 * @return string A base64 encoded copy of the JSON encoded paramaters
	 */
	public static function get_hashed_parameters( $parameters ) {
		$parameters['hash'] = self::get_parameter_hash( wp_json_encode( $parameters ) );

		return base64_encode( wp_json_encode( $parameters ) );
	}

	/**
	 * Validates that a hash of the parameter array matches the included hash parameter
	 *
	 * @param array $parameters An array of query parameters.
	 * @return array|false An array of the parameters minus the hash, false if they don't match.
	 */
	public static function get_validated_parameters( $parameters ) {
		if ( empty( $parameters['hash'] ) ) {
			return false;
		}

		$return_hash = $parameters['hash'];
		unset( $parameters['hash'] );

		$hash = self::get_parameter_hash( wp_json_encode( $parameters ) );
		if ( ! hash_equals( $hash, $return_hash ) ) {
			return false;
		}

		return $parameters;
	}

	public static function cleanup_request_parameters( $params ) {
		Keyring_Util::debug( 'cleanup_request_parameters' );
		Keyring_Util::debug( $params );
		if ( is_array( $params ) ) {
			foreach ( $params as $key => $val ) {
				// Some services double-encode things (Strava), so we need to clean up parameter names before using
				if ( substr( $key, 0, 4 ) === 'amp;' ) {
					$params[ substr( $key, 4 ) ] = $val;
					unset( $params[ $key ] );
				}
			}
		}
		return $params;
	}
}
