<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\String;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class ConstructedStringTest extends TestCase
{
    #[Test]
    public function create(): ConstructedString
    {
        $cs = ConstructedString::createWithTag(
            Element::TYPE_OCTET_STRING,
            OctetString::create('Hello'),
            OctetString::create('World')
        )->withIndefiniteLength();
        static::assertInstanceOf(ConstructedString::class, $cs);
        return $cs;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_OCTET_STRING, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): ConstructedString
    {
        $el = ConstructedString::fromDER($data);
        static::assertInstanceOf(ConstructedString::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    #[Test]
    #[Depends('create')]
    public function strings(ConstructedString $cs)
    {
        static::assertSame(['Hello', 'World'], $cs->strings());
    }

    #[Test]
    #[Depends('create')]
    public function stringable(ConstructedString $cs)
    {
        static::assertSame('HelloWorld', $cs->string());
        static::assertSame('HelloWorld', strval($cs));
    }

    #[Test]
    #[Depends('create')]
    public function isPseudoType(ConstructedString $cs)
    {
        static::assertTrue($cs->isType(Element::TYPE_CONSTRUCTED_STRING));
    }

    #[Test]
    #[Depends('create')]
    public function unspecified(ConstructedString $cs)
    {
        $ut = UnspecifiedType::create($cs);
        static::assertInstanceOf(ConstructedString::class, $ut->asConstructedString());
    }

    #[Test]
    public function unspecifiedFail()
    {
        $ut = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Constructed String expected, got primitive NULL');
        $ut->asConstructedString();
    }

    #[Test]
    public function createFromElements()
    {
        $cs = ConstructedString::create(OctetString::create('Hello'), OctetString::create('World'));
        static::assertInstanceOf(ConstructedString::class, $cs);
        return $cs;
    }

    #[Test]
    #[Depends('createFromElements')]
    public function fromElementsTag(ConstructedString $cs)
    {
        static::assertSame(Element::TYPE_OCTET_STRING, $cs->tag());
    }

    #[Test]
    public function createNoElementsFail()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No elements, unable to determine type tag');
        ConstructedString::create();
    }

    #[Test]
    public function createMixedElementsFail()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('All elements in constructed string must have the same type');
        ConstructedString::create(OctetString::create('Hello'), BitString::create('World'));
    }

    #[Test]
    #[DataProvider('provideStringType')]
    public function stringTypeAndConcatenate(StringType $el)
    {
        $str = $el->string();
        $cs = ConstructedString::create($el, $el)->withIndefiniteLength();
        $der = $cs->toDER();
        $ut = ConstructedString::fromDER($der)->asUnspecified();
        $s = $ut->asString();
        static::assertInstanceOf(StringType::class, $s);
        static::assertSame("{$str}{$str}", $s->string());
    }

    public static function provideStringType(): iterable
    {
        static $str = 'test';
        yield [BitString::create($str)];
        yield [BMPString::create($str)];
        yield [CharacterString::create($str)];
        yield [GeneralString::create($str)];
        yield [GraphicString::create($str)];
        yield [IA5String::create($str)];
        yield [NumericString::create('1234')];
        yield [ObjectDescriptor::create($str)];
        yield [OctetString::create($str)];
        yield [PrintableString::create($str)];
        yield [T61String::create($str)];
        yield [UniversalString::create($str)];
        yield [UTF8String::create($str)];
        yield [VideotexString::create($str)];
        yield [VisibleString::create($str)];
        yield [GeneralizedTime::fromString('now')];
        yield [UTCTime::fromString('now')];
    }
}
