<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;
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
        $cn = new CommonNameValue(self::CN);
        $desc = new DescriptionValue(self::DESC);
        $ext = new SubjectDirectoryAttributesExtension(false, $cn->toAttribute(), $desc->toAttribute());
        $this->assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        $this->assertFalse($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cN(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertEquals(self::CN, $ext->firstOf(AttributeType::OID_COMMON_NAME) ->first() ->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function desc(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertEquals(self::DESC, $ext->firstOf(AttributeType::OID_DESCRIPTION) ->first() ->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertTrue($ext->has('cn'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertFalse($ext->has('ou'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(1, $ext->allOf('cn'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOfNone(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(0, $ext->allOf('ou'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(2, $ext->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(2, $ext);
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
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $ext = new SubjectDirectoryAttributesExtension(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    /**
     * @test
     */
    public function decodeEmptyFail()
    {
        $seq = new Sequence();
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES),
            new OctetString($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        SubjectDirectoryAttributesExtension::fromASN1($ext_seq);
    }
}
