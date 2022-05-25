<?php

/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              https://www.fiverr.com/junaidzx90
 * @since             1.0.0
 * @package           2fa_Email_Authentication
 *
 * @wordpress-plugin
 * Plugin Name:       2FA email authentication
 * Plugin URI:        https://www.fiverr.com
 * Description:       This plugin is used for WordPress 2-factor authentication login.
 * Version:           1.0.0
 * Author:            Developer Junayed
 * Author URI:        https://www.fiverr.com/junaidzx90
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       2fa-email-authentication
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Currently plugin version.
 * Start at version 1.0.0 and use SemVer - https://semver.org
 * Rename this for your plugin and update it as you release new versions.
 */
define( '2FA_EMAIL_AUTHENTICATION_VERSION', '1.0.0' );

add_filter( 'wp_authenticate_user', 'checking_user_credentials_validity', 10, 2 );
function checking_user_credentials_validity( $user, $password ) {
	if(wp_check_password($password, $user->user_pass, $user->ID)){ 
		// Calling a function to send message
		do_action( 'send_verification', $user, $password );
		$message = esc_html__( 'A verification link sent to your email address.', '2fa-email-authentication');
		return new WP_Error( 'is_user_valid', $message ); // Prevent the access with the error exception for valid user
	}else{
		return $user; // If any errors occur then keep it as it was
	}
}

add_filter( 'login_errors', 'handling_the_success_message' );
function handling_the_success_message($error){
	global $errors;
    $err_codes = $errors->get_error_codes();

	if ( in_array( 'is_user_valid', $err_codes ) ) {
        echo '<div class="message success">'.$error.'</div>'; // just need to echo the the html alert for changing the error to success message
		exit; // Exit from the current stage to ignore the login form
    }else{
		return $error; // for other error exceptions
	}
}

add_action("send_verification", "send_verification_link", 10, 2);
function send_verification_link($user, $password){
	$stringLength = 6;
	$token = substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($stringLength/strlen($x)) )), 1, $stringLength);
	$verificationCode = $token;

	$userLocalIp = getenv("REMOTE_ADDR");

	$authentication_array = array(
		'access' => [
			'user_login'    => $user->user_login,
			'user_password' => $password,
		],
		'token' => [
			'user_email' => $user->user_email,
			'user_ip' => $userLocalIp,
			'verification_code' => $verificationCode
		]
	);

	// Make 128bit format string with the md5
	$uniqueString = md5(json_encode($authentication_array['token']));

	set_transient( $uniqueString, $authentication_array,  MINUTE_IN_SECONDS * 15 ); // Set all the data into transient in the database (The transient key is the identifier)
	
	$url = wp_login_url( get_home_url( ) );
	$url .= "&token=$uniqueString"; // URL for send to the message
	
	$to = $user->user_email;
	$subject = 'Verify Your Email Address';
	$body = '<div style="padding: 5px;">
				<h3 style="margin-bottom: 4px; font-size: 16px;">Please verify your email address</h3>
				<p style="margin: 0;">Please click below to verify your email address. Once complete, you will be able to login to the site.</p>
				<p><a target="_blank" style="padding: 5px 15px; border-radius: 3px; text-decoration: none; background-color: #0073aa; color: #fff; margin-top: 10px; display: inline-block;" href="'.$url.'">Verify</a></p>
			</div>';
	$headers = array('Content-Type: text/html; charset=UTF-8');
	
	wp_mail( $to, $subject, $body, $headers );
}

add_action( "login_init", "checking_the_verification_link" );
function checking_the_verification_link(){ // This function will check the verification link and give access to the site
	if(isset($_GET['token'])){
		$_128bit = $_GET['token']; // It's md5() 128bit format string

		$cache_credentials = get_transient( $_128bit ); // Get transient by token (128bit string)
		
		if(is_array($cache_credentials) && sizeof($cache_credentials) > 0){
			
			$informations = [];
			if(array_key_exists('token', $cache_credentials)){ // point to the correct data
				$informations = $cache_credentials['token'];
			}

			if(sizeof($informations) > 0){
				$transient_128bit = md5(json_encode($informations));

				if($transient_128bit === $_128bit){ // Matching transient values with url string
					remove_action( "wp_authenticate_user", "checking_user_credentials_validity" ); // Remove the wp_authenticate_user
					$user = wp_signon( $cache_credentials['access'], true );
					wp_set_current_user ( $user->ID ); // Set the current user detail
        			wp_set_auth_cookie  ( $user->ID ); // Set auth details in cookie
	
					if ( !is_wp_error( $user ) ) {
						delete_transient( $_128bit ); // If got access then delete the transient
						wp_safe_redirect(home_url( '/' ));
						exit;
					}else{
						delete_transient( $_128bit ); // delete the transient if exist
						// echo $user->get_error_message();
					}
				}
			}
		}
	}
}