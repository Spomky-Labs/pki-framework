<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr\Attribute;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): ExtensionRequestValue
    {
        $value = ExtensionRequestValue::create(Extensions::create());
        static::assertInstanceOf(ExtensionRequestValue::class, $value);
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
    public function decode($der): ExtensionRequestValue
    {
        $value = ExtensionRequestValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(ExtensionRequestValue::class, $value);
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
        static::assertSame(ExtensionRequestValue::OID, $value->oid());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(ExtensionRequestValue $value)
    {
        static::assertInstanceOf(Extensions::class, $value->extensions());
    }

    #[Test]
    #[Depends('create')]
    public function stringValue(ExtensionRequestValue $value)
    {
        static::assertIsString($value->stringValue());
    }

    #[Test]
    #[Depends('create')]
    public function equalityMatchingRule(ExtensionRequestValue $value)
    {
        static::assertInstanceOf(MatchingRule::class, $value->equalityMatchingRule());
    }

    #[Test]
    #[Depends('create')]
    public function rFC2253String(ExtensionRequestValue $value)
    {
        static::assertIsString($value->rfc2253String());
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(ExtensionRequestValue $value)
    {
        static::assertIsString(strval($value));
    }
}
