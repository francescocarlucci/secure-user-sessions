<?php
/**
 * Plugin Name: Secure User Sessions
 * Description: Implements an additional security layer and ties the user session to the IP used upon login.
 * Version: 0.0.1
 * Author: Francesco Carlucci
 * Author URI: https://francescocarlucci.com/
 */

function sus_get_user_ip() {

    if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {

        $ip = $_SERVER['HTTP_CLIENT_IP'];

    } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {

        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];

    } else {

        $ip = $_SERVER['REMOTE_ADDR'];

    }

    return $ip;

}

add_action( 'wp_login', 'sus_store_user_ip', 10, 2 );
function sus_store_user_ip( $user_login, $user ) {
    
    $ip = sus_get_user_ip();

    update_user_meta( $user->ID, 'sus_user_ip', sanitize_text_field( $ip ) );

}

add_filter( 'determine_current_user', 'sus_validate_user_ip' );
function sus_validate_user_ip( $user_id ) {

    if ( ! $user_id ) {

        return false;
    
    }

    $stored_ip = get_user_meta( $user_id, 'sus_user_ip', true );

    // NOTE the defense only triggers if the session has an IP associated
    if ( ! $stored_ip || empty( $stored_ip ) ) {

        return $user_id;

    }

    $current_ip = sus_get_user_ip();

    if ( $stored_ip !== $current_ip ) {

        $sessions = WP_Session_Tokens::get_instance($user_id);

        $sessions->destroy_all();

        return false;

    }

    return $user_id;

}
