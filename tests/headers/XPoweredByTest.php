<?php

namespace shyevsa\security\tests\headers;

use shyevsa\security\headers\XPoweredBy;
use shyevsa\security\tests\TestCase;

class XPoweredByTest extends TestCase
{
    /**
     * @var XPoweredBy
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new XPoweredBy('Hyperia');
    }

    public function testGetValue(): void
    {
        $this->assertSame('Hyperia', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('X-Powered-By', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }
}
