<?php

/* oAuth Signature OOP implementation 
 Nicolas KERMARC 
 www.deegr.com
 do what the fuck you want to do with it LICENSE
*/

class oAuthSignature {
	
	public $http_method;
	public $oauth_params;
	public $secret_params;
	public $extra_params;
	public $uri;

	
	public function __construct() {
		
	}
	
	/* Return the sorted array of parameters
		We are encoding key and values first.
	 */
	public function sortParams() {
		
		$tab = array_merge($this->oauth_params,$this->extra_params);
		
		
		$tab_out = array();
	
		
		foreach ($tab as $key => $value) {
			$tab_out[rawurlencode($key)] = rawurlencode($value);
	
	
		}
		

		
		
		
		ksort($tab_out);
		
		

		
	
		unset($key);
		unset($value);
		unset($tab);
		return $tab_out;
		
		
	}
	
	/* Prepare the parameters concatenation string */
	public function prepareParams() {
		
		$paramsSorted = $this->sortParams();
		
		$count = 0;

		$params_string = "";
		$last = sizeof($paramsSorted) - 1;
		foreach ($paramsSorted as $key => $value) {
			
			if ($count == 0) {
				$params_string = $key."=".$value."&";
			}
			else if ($count == $last) {
				$params_string .= $key."=".$value;
			}
			else {
				$params_string .= $key."=".$value."&";
			}
			
			$count++;
		}
		
		
		unset($count);
		unset($paramsSorted);
		
		
		
		return $params_string;
		
		
		
	}
	
	
	/* Get the salt for HMAC SHA1. */
	public function getCryptKey() {
		if (isset($this->secret_params["token_secret"])) {
			return rawurlencode($this->secret_params["consumer_secret"])."&".rawurlencode($this->secret_params["token_secret"]);
		} else {
			return rawurlencode($this->secret_params["consumer_secret"])."&";
		}
	}
	
	
	
	
	/* Final method to get signature. */
	public function buildSignature() {
		$string = strtoupper($this->http_method)."&".rawurlencode($this->uri)."&".rawurlencode($this->prepareParams());
		
	
		
		
		return base64_encode(hash_hmac('sha1', $string,$this->getCryptKey(),true));
	}
	
	
	
	
}


