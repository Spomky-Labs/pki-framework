<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\UtcTime;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function encode()
    {
        $el = UTCTime::create(new DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006'));
        static::assertSame("\x17\x0d" . '060102220405Z', $el->toDER());
    }
}
