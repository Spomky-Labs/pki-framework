<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\UtcTime;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\UTCTime;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    public function testEncode()
    {
        $el = new UTCTime(new \DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006'));
        $this->assertEquals("\x17\x0d" . '060102220405Z', $el->toDER());
    }
}
