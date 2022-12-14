<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

use Exception;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\ASN1\Type\TimeType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

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
        static::assertInstanceOf(TimeType::class, $el);
        return $el;
    }

    /**
     * @test
     */
    public function fromStringWithTz()
    {
        $el = GeneralizedTime::fromString(self::VALUE, 'Europe/Helsinki');
        static::assertInstanceOf(TimeType::class, $el);
    }

    /**
     * @test
     */
    public function fromInvalidStringFail()
    {
        $this->expectException(Exception::class);
        GeneralizedTime::fromString('fail');
    }

    /**
     * @test
     */
    public function fromStringWithInvalidTzFail()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid timezone.');
        GeneralizedTime::fromString(self::VALUE, 'nope');
    }

    /**
     * @depends fromString
     *
     * @test
     */
    public function wrapped(TimeType $time)
    {
        $wrap = UnspecifiedType::create($time->asElement());
        static::assertInstanceOf(TimeType::class, $wrap->asTime());
    }
}
