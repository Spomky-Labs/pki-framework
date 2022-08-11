<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\UtcTime;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;
use SpomkyLabs\Pki\ASN1\Type\TimeType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class UTCTimeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = UTCTime::fromString('Mon Jan 2 15:04:05 MST 2006');
        static::assertInstanceOf(UTCTime::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_UTC_TIME, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): UTCTime
    {
        $el = UTCTime::fromDER($data);
        static::assertInstanceOf(UTCTime::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(TimeType $ref, TimeType $el)
    {
        static::assertEquals($ref->dateTime()->getTimestamp(), $el->dateTime()->getTimestamp());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(UTCTime::class, $wrap->asUTCTime());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UTCTime expected, got primitive NULL');
        $wrap->asUTCTime();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringable(TimeType $time)
    {
        static::assertEquals('060102220405Z', $time->string());
        static::assertEquals('060102220405Z', strval($time));
    }
}
