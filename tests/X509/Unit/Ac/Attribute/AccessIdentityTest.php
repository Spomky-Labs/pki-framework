<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
    public function create(): AccessIdentityAttributeValue
    {
        $value = AccessIdentityAttributeValue::create(
            UniformResourceIdentifier::create(self::SERVICE_URI),
            UniformResourceIdentifier::create(self::IDENT_URI)
        );
        static::assertInstanceOf(AccessIdentityAttributeValue::class, $value);
        return $value;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AttributeValue $value): string
    {
        $el = $value->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): AccessIdentityAttributeValue
    {
        $value = AccessIdentityAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(AccessIdentityAttributeValue::class, $value);
        return $value;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AttributeValue $ref, AttributeValue $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function oID(AttributeValue $value)
    {
        static::assertSame(AccessIdentityAttributeValue::OID, $value->oid());
    }

    #[Test]
    #[Depends('create')]
    public function service(AccessIdentityAttributeValue $value)
    {
        static::assertSame(self::SERVICE_URI, $value->service()->string());
    }

    #[Test]
    #[Depends('create')]
    public function ident(AccessIdentityAttributeValue $value)
    {
        static::assertSame(self::IDENT_URI, $value->ident()->string());
    }

    #[Test]
    #[Depends('create')]
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasAccessIdentity());
        return $attribs;
    }

    #[Test]
    #[Depends('attributes')]
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(AccessIdentityAttributeValue::class, $attribs->accessIdentity());
    }
}
