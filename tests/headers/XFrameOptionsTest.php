<?php

namespace shyevsa\security\tests\headers;

use shyevsa\security\headers\XFrameOptions;
use shyevsa\security\tests\TestCase;

class XFrameOptionsTest extends TestCase
{
    /**
     * @var XFrameOptions
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new XFrameOptions('DENY');
    }

    public function testGetValue(): void
    {
        $this->assertSame('DENY', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('X-Frame-Options', $this->header->getName());
    }

    public function testValidDirective(): void
    {
        $this->assertTrue($this->header->isValid());
    }

    public function testInvalidDirective(): void
    {
        $policy = new XFrameOptions('ALLOW-FROM https://www.hyperia.sk');
        $this->assertFalse($policy->isValid());
    }
}
