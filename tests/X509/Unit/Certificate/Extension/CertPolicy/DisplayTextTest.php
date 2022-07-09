<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\BaseString;
use Sop\ASN1\Type\Primitive\BMPString;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\Primitive\VisibleString;
use Sop\ASN1\Type\StringType;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class DisplayTextTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $dt = DisplayText::fromString('test');
        static::assertInstanceOf(DisplayText::class, $dt);
        return $dt;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(DisplayText $dt)
    {
        $el = $dt->toASN1();
        static::assertInstanceOf(StringType::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $qual = DisplayText::fromASN1(BaseString::fromDER($data));
        static::assertInstanceOf(DisplayText::class, $qual);
        return $qual;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(DisplayText $ref, DisplayText $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(DisplayText $dt)
    {
        static::assertEquals('test', $dt->string());
    }

    /**
     * @test
     */
    public function encodeIA5String()
    {
        $dt = new DisplayText('', Element::TYPE_IA5_STRING);
        static::assertInstanceOf(IA5String::class, $dt->toASN1());
    }

    /**
     * @test
     */
    public function encodeVisibleString()
    {
        $dt = new DisplayText('', Element::TYPE_VISIBLE_STRING);
        static::assertInstanceOf(VisibleString::class, $dt->toASN1());
    }

    /**
     * @test
     */
    public function encodeBMPString()
    {
        $dt = new DisplayText('', Element::TYPE_BMP_STRING);
        static::assertInstanceOf(BMPString::class, $dt->toASN1());
    }

    /**
     * @test
     */
    public function encodeUTF8String()
    {
        $dt = new DisplayText('', Element::TYPE_UTF8_STRING);
        static::assertInstanceOf(UTF8String::class, $dt->toASN1());
    }

    /**
     * @test
     */
    public function encodeUnsupportedTypeFail()
    {
        $dt = new DisplayText('', Element::TYPE_NULL);
        $this->expectException(UnexpectedValueException::class);
        $dt->toASN1();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(DisplayText $dt)
    {
        static::assertIsString(strval($dt));
    }
}
