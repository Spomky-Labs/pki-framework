<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\GeneralizedTime;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\GeneralizedTime;

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
        $el = new GeneralizedTime(new DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006'));
        static::assertEquals("\x18\x0f" . '20060102220405Z', $el->toDER());
    }

    /**
     * @test
     */
    public function fractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.5", new DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        static::assertEquals("\x18\x11" . '20060102220405.5Z', $el->toDER());
    }

    /**
     * @test
     */
    public function multipleFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.99999", new DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        static::assertEquals("\x18\x15" . '20060102220405.99999Z', $el->toDER());
    }

    /**
     * @test
     */
    public function smallFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.000001", new DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        static::assertEquals("\x18\x16" . '20060102220405.000001Z', $el->toDER());
    }

    /**
     * @test
     */
    public function multipleZeroFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.000000", new DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        static::assertEquals("\x18\x0f" . '20060102220405Z', $el->toDER());
    }

    /**
     * @test
     */
    public function trailingFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = DateTimeImmutable::createFromFormat('U.u', "{$ts}.100000", new DateTimeZone('UTC'));
        $el = new GeneralizedTime($dt);
        static::assertEquals("\x18\x11" . '20060102220405.1Z', $el->toDER());
    }
}
