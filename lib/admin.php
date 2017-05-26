<?php

// Prevent editor from deleting, editing, or creating an administrator
// https://isabelcastillo.com/editor-role-manage-users-wordpress
class ISA_User_Caps {

	// Add our filters
	public function ISA_User_Caps() {
		add_filter( 'editable_roles', array( &$this, 'editable_roles' ) );
		add_filter( 'map_meta_cap', array( &$this, 'map_meta_cap' ), 10, 4 );
	}

	// Remove 'Administrator' from the list of roles if the current user is not an admin
	public function editable_roles( $roles ) {

		// Get all roles which can manage options
		$roles_with_manage_options = [];
		foreach ( $roles as $iKey => $role ) {
			if ( $role['capabilities']['manage_options'] == true ) {

				// Check if the value is already added to the array
				if ( ! in_array( $iKey, $roles_with_manage_options ) ) {
					$roles_with_manage_options[$iKey] = $iKey;
				}
			}
		}

		foreach ( $roles_with_manage_options as $iKey => $role ) {
			if ( in_array( $iKey, $roles_with_manage_options ) && ! current_user_can( $roles_with_manage_options ) ) {
            	unset( $roles[$iKey] );
			}
		}

		return $roles;
	}

	// If someone is trying to edit or delete an admin and that user isn't an admin, don't allow it
	public function map_meta_cap( $caps, $cap, $user_id, $args ) {
		switch ( $cap ) {
			case 'edit_user':
			case 'remove_user':
			case 'promote_user':
				if ( isset( $args[0] ) && $args[0] == $user_id ) {
					break;
				} elseif ( ! isset( $args[0] ) ) {
					$caps[] = 'do_not_allow';
				}
				$other = new WP_User( absint( $args[0] ) );
				if ( $other->has_cap( 'manage_options' ) ) {
					if ( ! current_user_can( 'manage_options' ) ) {
						$caps[] = 'do_not_allow';
					}
				}
				break;
			case 'delete_user':
			case 'delete_users':
				if ( ! isset( $args[0] ) ) {
					break;
				}
				$other = new WP_User( absint( $args[0] ) );
				if ( $other->has_cap( 'manage_options' ) ) {
					if ( ! current_user_can( 'manage_options' ) ) {
						$caps[] = 'do_not_allow';
					}
				}
				break;
			default:
				break;
		}
		return $caps;
	}
}

$isa_user_caps = new ISA_User_Caps();