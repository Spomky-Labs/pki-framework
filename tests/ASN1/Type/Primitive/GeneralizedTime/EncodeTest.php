<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\GeneralizedTime;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\GeneralizedTime;

/**
 * @group encode
 * @group generalized-time
 *
 * @internal
 */
class EncodeTest extends TestCase
{
    public function testEncode()
    {
        $el = new GeneralizedTime(
            new \DateTimeImmutable('Mon Jan 2 15:04:05 MST 2006')
        );
        $this->assertEquals("\x18\x0f" . '20060102220405Z', $el->toDER());
    }

    public function testFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = \DateTimeImmutable::createFromFormat(
            'U.u',
            "{$ts}.5",
            new \DateTimeZone('UTC')
        );
        $el = new GeneralizedTime($dt);
        $this->assertEquals("\x18\x11" . '20060102220405.5Z', $el->toDER());
    }

    public function testMultipleFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = \DateTimeImmutable::createFromFormat(
            'U.u',
            "{$ts}.99999",
            new \DateTimeZone('UTC')
        );
        $el = new GeneralizedTime($dt);
        $this->assertEquals("\x18\x15" . '20060102220405.99999Z', $el->toDER());
    }

    public function testSmallFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = \DateTimeImmutable::createFromFormat(
            'U.u',
            "{$ts}.000001",
            new \DateTimeZone('UTC')
        );
        $el = new GeneralizedTime($dt);
        $this->assertEquals("\x18\x16" . '20060102220405.000001Z', $el->toDER());
    }

    public function testMultipleZeroFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = \DateTimeImmutable::createFromFormat(
            'U.u',
            "{$ts}.000000",
            new \DateTimeZone('UTC')
        );
        $el = new GeneralizedTime($dt);
        $this->assertEquals("\x18\x0f" . '20060102220405Z', $el->toDER());
    }

    public function testTrailingFractions()
    {
        $ts = strtotime('Mon Jan 2 15:04:05 MST 2006');
        $dt = \DateTimeImmutable::createFromFormat(
            'U.u',
            "{$ts}.100000",
            new \DateTimeZone('UTC')
        );
        $el = new GeneralizedTime($dt);
        $this->assertEquals("\x18\x11" . '20060102220405.1Z', $el->toDER());
    }
}
