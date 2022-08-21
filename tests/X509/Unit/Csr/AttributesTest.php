<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr;

use LogicException;
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
    /**
     * @test
     */
    public function create()
    {
        $attribs = Attributes::fromAttributeValues(ExtensionRequestValue::create(new Extensions()));
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Attributes $attribs)
    {
        $seq = $attribs->toASN1();
        static::assertInstanceOf(Set::class, $seq);
        return $seq->toDER();
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
        $attribs = Attributes::fromASN1(Set::fromDER($data));
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Attributes $ref, Attributes $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensionRequest(Attributes $attribs)
    {
        static::assertInstanceOf(ExtensionRequestValue::class, $attribs->extensionRequest());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(Attributes $attribs)
    {
        static::assertContainsOnlyInstancesOf(Attribute::class, $attribs->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Attributes $attribs)
    {
        static::assertCount(1, $attribs);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(Attributes $attribs)
    {
        $values = [];
        foreach ($attribs as $attr) {
            $values[] = $attr;
        }
        static::assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOfFail(Attributes $attribs)
    {
        $this->expectException(UnexpectedValueException::class);
        $attribs->firstOf('1.3.6.1.3');
    }

    /**
     * @test
     */
    public function noExtensionRequestFail()
    {
        $attribs = Attributes::create();
        $this->expectException(LogicException::class);
        $attribs->extensionRequest();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAdditional(Attributes $attribs)
    {
        $attribs = $attribs->withAdditional(Attribute::fromAttributeValues(CommonNameValue::create('Test')));
        static::assertCount(2, $attribs);
        return $attribs;
    }

    /**
     * @depends withAdditional
     *
     * @test
     */
    public function encodeWithAdditional(Attributes $attribs)
    {
        $seq = $attribs->toASN1();
        static::assertInstanceOf(Set::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encodeWithAdditional
     *
     * @param string $data
     *
     * @test
     */
    public function decodeWithAdditional($data)
    {
        $attribs = Attributes::fromASN1(Set::fromDER($data));
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends decodeWithAdditional
     *
     * @test
     */
    public function decodedWithAdditionalHasCustomAttribute(Attributes $attribs)
    {
        static::assertInstanceOf(
            CommonNameValue::class,
            $attribs->firstOf(AttributeType::OID_COMMON_NAME)
                ->first()
        );
    }
}
