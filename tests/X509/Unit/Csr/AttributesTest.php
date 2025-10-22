<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use SpomkyLabs\Pki\X509\CertificationRequest\Attributes;
use UnexpectedValueException;

/**
 * @internal
 */
final class AttributesTest extends TestCase
{
    #[Test]
    public function create(): Attributes
    {
        $attribs = Attributes::fromAttributeValues(ExtensionRequestValue::create(Extensions::create()));
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Attributes $attribs): string
    {
        $seq = $attribs->toASN1();
        static::assertInstanceOf(Set::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): Attributes
    {
        $attribs = Attributes::fromASN1(Set::fromDER($data));
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Attributes $ref, Attributes $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function extensionRequest(Attributes $attribs)
    {
        static::assertInstanceOf(ExtensionRequestValue::class, $attribs->extensionRequest());
    }

    #[Test]
    #[Depends('create')]
    public function all(Attributes $attribs)
    {
        static::assertContainsOnlyInstancesOf(Attribute::class, $attribs->all());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Attributes $attribs)
    {
        static::assertCount(1, $attribs);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(Attributes $attribs)
    {
        $values = [];
        foreach ($attribs as $attr) {
            $values[] = $attr;
        }
        static::assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function firstOfFail(Attributes $attribs)
    {
        $this->expectException(UnexpectedValueException::class);
        $attribs->firstOf('1.3.6.1.3');
    }

    #[Test]
    public function noExtensionRequestFail()
    {
        $attribs = Attributes::create();
        $this->expectException(LogicException::class);
        $attribs->extensionRequest();
    }

    #[Test]
    #[Depends('create')]
    public function withAdditional(Attributes $attribs)
    {
        $attribs = $attribs->withAdditional(Attribute::fromAttributeValues(CommonNameValue::create('Test')));
        static::assertCount(2, $attribs);
        return $attribs;
    }

    #[Test]
    #[Depends('withAdditional')]
    public function encodeWithAdditional(Attributes $attribs)
    {
        $seq = $attribs->toASN1();
        static::assertInstanceOf(Set::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encodeWithAdditional')]
    public function decodeWithAdditional($data)
    {
        $attribs = Attributes::fromASN1(Set::fromDER($data));
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    #[Test]
    #[Depends('decodeWithAdditional')]
    public function decodedWithAdditionalHasCustomAttribute(Attributes $attribs)
    {
        static::assertInstanceOf(
            CommonNameValue::class,
            $attribs->firstOf(AttributeType::OID_COMMON_NAME)
                ->first()
        );
    }
}
