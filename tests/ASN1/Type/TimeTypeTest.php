<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Type\Primitive\GeneralizedTime;
use Sop\ASN1\Type\TimeType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @internal
 */
final class TimeTypeTest extends TestCase
{
    final public const VALUE = 'Mon Jan 2 15:04:05 MST 2006';

    /**
     * @test
     */
    public function fromString()
    {
        $el = GeneralizedTime::fromString(self::VALUE);
        $this->assertInstanceOf(TimeType::class, $el);
        return $el;
    }

    /**
     * @test
     */
    public function fromStringWithTz()
    {
        $el = GeneralizedTime::fromString(self::VALUE, 'Europe/Helsinki');
        $this->assertInstanceOf(TimeType::class, $el);
    }

    /**
     * @test
     */
    public function fromInvalidStringFail()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to create DateTime');
        GeneralizedTime::fromString('fail');
    }

    /**
     * @test
     */
    public function fromStringWithInvalidTzFail()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to create DateTime');
        GeneralizedTime::fromString(self::VALUE, 'nope');
    }

    /**
     * @depends fromString
     *
     * @test
     */
    public function wrapped(TimeType $time)
    {
        $wrap = new UnspecifiedType($time->asElement());
        $this->assertInstanceOf(TimeType::class, $wrap->asTime());
    }
}
