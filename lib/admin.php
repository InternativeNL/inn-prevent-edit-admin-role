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
		if ( isset( $roles['administrator'] ) && ! current_user_can( 'administrator' ) ) {
		  unset( $roles['administrator'] );
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
				if ( $other->has_cap( 'administrator' ) ) {
					if ( ! current_user_can( 'administrator' ) ) {
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
				if ( $other->has_cap( 'administrator' ) ) {
					if ( ! current_user_can( 'administrator' ) ) {
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