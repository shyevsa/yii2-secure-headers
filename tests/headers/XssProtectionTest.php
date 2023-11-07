<?php

namespace shyevsa\security\tests\headers;

use shyevsa\security\headers\XssProtection;
use shyevsa\security\tests\TestCase;

class XssProtectionTest extends TestCase
{
    /**
     * @var XssProtection
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new XssProtection(true, 'example.com/r/d/xss/enforce');
    }

    public function testGetValue(): void
    {
        $this->assertSame('1; mode=block; report=example.com/r/d/xss/enforce', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('X-XSS-Protection', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }
}
