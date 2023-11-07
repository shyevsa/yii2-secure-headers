<?php

namespace shyevsa\security\tests\headers;

use shyevsa\security\headers\ReferrerPolicy;
use shyevsa\security\tests\TestCase;

class ReferrerPolicyTest extends TestCase
{
    /**
     * @var ReferrerPolicy
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new ReferrerPolicy('no-referrer');
    }

    public function testGetValue(): void
    {
        $this->assertSame('no-referrer', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('Referrer-Policy', $this->header->getName());
    }

    public function dataProvider(): array
    {
        return [
            [false, ''],
            [false, 'none'],
            [true, 'unsafe-url']
        ];
    }

    /**
     * @param bool $expected
     * @param string $directive
     *
     * @dataProvider dataProvider
     */
    public function testValid(bool $expected, string $directive): void
    {
        $policy = new ReferrerPolicy($directive);

        $this->assertSame($expected, $policy->isValid());
    }
}
