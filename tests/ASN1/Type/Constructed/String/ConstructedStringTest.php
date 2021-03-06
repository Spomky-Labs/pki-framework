<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\String;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\ConstructedString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BMPString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\CharacterString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GraphicString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NumericString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectDescriptor;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\T61String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UniversalString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VideotexString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;
use SpomkyLabs\Pki\ASN1\Type\StringType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class ConstructedStringTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $cs = ConstructedString::createWithTag(
            Element::TYPE_OCTET_STRING,
            new OctetString('Hello'),
            new OctetString('World')
        )->withIndefiniteLength();
        static::assertInstanceOf(ConstructedString::class, $cs);
        return $cs;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_OCTET_STRING, $el->tag());
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
    public function decode(string $data): ConstructedString
    {
        $el = ConstructedString::fromDER($data);
        static::assertInstanceOf(ConstructedString::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function strings(ConstructedString $cs)
    {
        static::assertEquals(['Hello', 'World'], $cs->strings());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringable(ConstructedString $cs)
    {
        static::assertEquals('HelloWorld', $cs->string());
        static::assertEquals('HelloWorld', strval($cs));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isPseudoType(ConstructedString $cs)
    {
        static::assertTrue($cs->isType(Element::TYPE_CONSTRUCTED_STRING));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function unspecified(ConstructedString $cs)
    {
        $ut = UnspecifiedType::create($cs);
        static::assertInstanceOf(ConstructedString::class, $ut->asConstructedString());
    }

    /**
     * @test
     */
    public function unspecifiedFail()
    {
        $ut = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Constructed String expected, got primitive NULL');
        $ut->asConstructedString();
    }

    /**
     * @test
     */
    public function createFromElements()
    {
        $cs = ConstructedString::create(new OctetString('Hello'), new OctetString('World'));
        static::assertInstanceOf(ConstructedString::class, $cs);
        return $cs;
    }

    /**
     * @depends createFromElements
     *
     * @test
     */
    public function fromElementsTag(ConstructedString $cs)
    {
        static::assertEquals(Element::TYPE_OCTET_STRING, $cs->tag());
    }

    /**
     * @test
     */
    public function createNoElementsFail()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No elements, unable to determine type tag');
        ConstructedString::create();
    }

    /**
     * @test
     */
    public function createMixedElementsFail()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('All elements in constructed string must have the same type');
        ConstructedString::create(new OctetString('Hello'), new BitString('World'));
    }

    /**
     * @dataProvider provideStringType
     *
     * @test
     */
    public function stringTypeAndConcatenate(StringType $el)
    {
        $str = $el->string();
        $cs = ConstructedString::create($el, $el)->withIndefiniteLength();
        $der = $cs->toDER();
        $ut = ConstructedString::fromDER($der)->asUnspecified();
        $s = $ut->asString();
        static::assertInstanceOf(StringType::class, $s);
        static::assertEquals("{$str}{$str}", $s->string());
    }

    public function provideStringType(): iterable
    {
        static $str = 'test';
        yield [new BitString($str)];
        yield [new BMPString($str)];
        yield [new CharacterString($str)];
        yield [new GeneralString($str)];
        yield [new GraphicString($str)];
        yield [new IA5String($str)];
        yield [new NumericString('1234')];
        yield [new ObjectDescriptor($str)];
        yield [new OctetString($str)];
        yield [new PrintableString($str)];
        yield [new T61String($str)];
        yield [new UniversalString($str)];
        yield [new UTF8String($str)];
        yield [new VideotexString($str)];
        yield [new VisibleString($str)];
        yield [GeneralizedTime::fromString('now')];
        yield [UTCTime::fromString('now')];
    }
}
