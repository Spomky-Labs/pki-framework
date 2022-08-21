<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr\Attribute;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use function strval;

/**
 * @internal
 */
final class ExtensionRequestTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $value = ExtensionRequestValue::create(new Extensions());
        static::assertInstanceOf(ExtensionRequestValue::class, $value);
        return $value;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AttributeValue $value)
    {
        $el = $value->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $value = ExtensionRequestValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(ExtensionRequestValue::class, $value);
        return $value;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AttributeValue $ref, AttributeValue $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeValue $value)
    {
        static::assertEquals(ExtensionRequestValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(ExtensionRequestValue $value)
    {
        static::assertInstanceOf(Extensions::class, $value->extensions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringValue(ExtensionRequestValue $value)
    {
        static::assertIsString($value->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function equalityMatchingRule(ExtensionRequestValue $value)
    {
        static::assertInstanceOf(MatchingRule::class, $value->equalityMatchingRule());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rFC2253String(ExtensionRequestValue $value)
    {
        static::assertIsString($value->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(ExtensionRequestValue $value)
    {
        static::assertIsString(strval($value));
    }
}
