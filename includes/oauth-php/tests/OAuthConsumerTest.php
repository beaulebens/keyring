<?php

require 'common.php';

class OAuthConsumerTest extends PHPUnit\Framework\TestCase {
	public function testConvertToString() {
		$consumer = new OAuthConsumer('key', 'secret');
		$this->assertEquals('OAuthConsumer[key=key,secret=secret]', (string) $consumer);
	}
}