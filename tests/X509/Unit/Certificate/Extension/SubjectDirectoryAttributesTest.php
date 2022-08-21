<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;
use UnexpectedValueException;

/**
 * @internal
 */
final class SubjectDirectoryAttributesTest extends TestCase
{
    final public const CN = 'Test';

    final public const DESC = 'Description';

    /**
     * @test
     */
    public function create()
    {
        $cn = CommonNameValue::create(self::CN);
        $desc = DescriptionValue::create(self::DESC);
        $ext = SubjectDirectoryAttributesExtension::create(false, $cn->toAttribute(), $desc->toAttribute());
        static::assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertFalse($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
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
        $ext = SubjectDirectoryAttributesExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cN(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertEquals(self::CN, $ext->firstOf(AttributeType::OID_COMMON_NAME)->first()->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function desc(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertEquals(self::DESC, $ext->firstOf(AttributeType::OID_DESCRIPTION)->first()->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertTrue($ext->has('cn'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertFalse($ext->has('ou'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertCount(1, $ext->allOf('cn'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOfNone(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertCount(0, $ext->allOf('ou'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertCount(2, $ext->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(SubjectDirectoryAttributesExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(SubjectDirectoryAttributesExtension $ext)
    {
        $values = [];
        foreach ($ext as $attr) {
            $values[] = $attr;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $ext = SubjectDirectoryAttributesExtension::create(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    /**
     * @test
     */
    public function decodeEmptyFail()
    {
        $seq = Sequence::create();
        $ext_seq = Sequence::create(
            ObjectIdentifier::create(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES),
            OctetString::create($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        SubjectDirectoryAttributesExtension::fromASN1($ext_seq);
    }
}
