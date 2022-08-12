<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AccessIdentityTest extends TestCase
{
    final public const SERVICE_URI = 'urn:service';

    final public const IDENT_URI = 'urn:username';

    /**
     * @test
     */
    public function create()
    {
        $value = AccessIdentityAttributeValue::create(
            new UniformResourceIdentifier(self::SERVICE_URI),
            new UniformResourceIdentifier(self::IDENT_URI)
        );
        static::assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        $value = AccessIdentityAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        static::assertEquals(AccessIdentityAttributeValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function service(AccessIdentityAttributeValue $value)
    {
        static::assertEquals(self::SERVICE_URI, $value->service());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function ident(AccessIdentityAttributeValue $value)
    {
        static::assertEquals(self::IDENT_URI, $value->ident());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasAccessIdentity());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(AccessIdentityAttributeValue::class, $attribs->accessIdentity());
    }
}
