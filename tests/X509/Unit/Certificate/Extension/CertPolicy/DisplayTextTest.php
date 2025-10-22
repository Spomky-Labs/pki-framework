<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\BaseString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BMPString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;
use SpomkyLabs\Pki\ASN1\Type\StringType;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class DisplayTextTest extends TestCase
{
    #[Test]
    public function create(): DisplayText
    {
        $dt = DisplayText::fromString('test');
        static::assertInstanceOf(DisplayText::class, $dt);
        return $dt;
    }

    #[Test]
    #[Depends('create')]
    public function encode(DisplayText $dt): string
    {
        $el = $dt->toASN1();
        static::assertInstanceOf(StringType::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): DisplayText
    {
        $qual = DisplayText::fromASN1(BaseString::fromDER($data));
        static::assertInstanceOf(DisplayText::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(DisplayText $ref, DisplayText $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(DisplayText $dt)
    {
        static::assertSame('test', $dt->string());
    }

    #[Test]
    public function encodeIA5String()
    {
        $dt = DisplayText::create('', Element::TYPE_IA5_STRING);
        static::assertInstanceOf(IA5String::class, $dt->toASN1());
    }

    #[Test]
    public function encodeVisibleString()
    {
        $dt = DisplayText::create('', Element::TYPE_VISIBLE_STRING);
        static::assertInstanceOf(VisibleString::class, $dt->toASN1());
    }

    #[Test]
    public function encodeBMPString()
    {
        $dt = DisplayText::create('', Element::TYPE_BMP_STRING);
        static::assertInstanceOf(BMPString::class, $dt->toASN1());
    }

    #[Test]
    public function encodeUTF8String()
    {
        $dt = DisplayText::create('', Element::TYPE_UTF8_STRING);
        static::assertInstanceOf(UTF8String::class, $dt->toASN1());
    }

    #[Test]
    public function encodeUnsupportedTypeFail()
    {
        $dt = DisplayText::create('', Element::TYPE_NULL);
        $this->expectException(UnexpectedValueException::class);
        $dt->toASN1();
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(DisplayText $dt)
    {
        static::assertIsString(strval($dt));
    }
}
