<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\RelativeName;

/**
 * @internal
 */
final class RelativeNameTest extends TestCase
{
    #[Test]
    public function create(): RelativeName
    {
        $name = RelativeName::create(
            RDN::create(AttributeTypeAndValue::fromAttributeValue(CommonNameValue::create('Test')))
        );
        static::assertInstanceOf(RelativeName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(RelativeName $name): string
    {
        $el = $name->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): RelativeName
    {
        $name = RelativeName::fromTaggedType(TaggedType::fromDER($data));
        static::assertInstanceOf(RelativeName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(RelativeName $ref, RelativeName $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function rDN(RelativeName $name)
    {
        $rdn = $name->rdn();
        static::assertInstanceOf(RDN::class, $rdn);
    }
}
