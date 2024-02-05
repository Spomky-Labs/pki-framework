<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\GeneralizedTime;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function encode()
    {
        $el = GeneralizedTime::create(new DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006'));
        static::assertSame("\x18\x0f" . '20060102220405Z', $el->toDER());
    }

    #[Test]
    public function fractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.5", new DateTimeZone('UTC'));
        $el = GeneralizedTime::create($dt);
        static::assertSame("\x18\x11" . '20060102220405.5Z', $el->toDER());
    }

    #[Test]
    public function multipleFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.99999", new DateTimeZone('UTC'));
        $el = GeneralizedTime::create($dt);
        static::assertSame("\x18\x15" . '20060102220405.99999Z', $el->toDER());
    }

    #[Test]
    public function smallFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.000001", new DateTimeZone('UTC'));
        $el = GeneralizedTime::create($dt);
        static::assertSame("\x18\x16" . '20060102220405.000001Z', $el->toDER());
    }

    #[Test]
    public function multipleZeroFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.000000", new DateTimeZone('UTC'));
        $el = GeneralizedTime::create($dt);
        static::assertSame("\x18\x0f" . '20060102220405Z', $el->toDER());
    }

    #[Test]
    public function trailingFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.100000", new DateTimeZone('UTC'));
        $el = GeneralizedTime::create($dt);
        static::assertSame("\x18\x11" . '20060102220405.1Z', $el->toDER());
    }
}
