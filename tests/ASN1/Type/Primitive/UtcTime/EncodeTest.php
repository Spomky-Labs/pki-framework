<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\UtcTime;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\UTCTime;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function encode()
    {
        $el = new UTCTime(new DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006'));
        static::assertEquals("\x17\x0d" . '060102220405Z', $el->toDER());
    }
}
