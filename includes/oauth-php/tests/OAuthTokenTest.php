<?php

require_once dirname(__FILE__) . '/common.php';

class OAuthTokenTest extends PHPUnit\Framework\TestCase {
	public function testSerialize() {
		$token = new OAuthToken('token', 'secret');
		$this->assertEquals('oauth_token=token&oauth_token_secret=secret', $token->to_string());
		
		$token = new OAuthToken('token&', 'secret%');
		$this->assertEquals('oauth_token=token%26&oauth_token_secret=secret%25', $token->to_string());
	}
	public function testConvertToString() {
		$token = new OAuthToken('token', 'secret');
		$this->assertEquals('oauth_token=token&oauth_token_secret=secret', (string) $token);
		
		$token = new OAuthToken('token&', 'secret%');
		$this->assertEquals('oauth_token=token%26&oauth_token_secret=secret%25', (string) $token);
	}
}