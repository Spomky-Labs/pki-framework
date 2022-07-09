<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Constructed\Set;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Set;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Structure;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class SetTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $set = new Set(new NullType(), new Boolean(true));
        $this->assertInstanceOf(Structure::class, $set);
        return $set;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_SET, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): Set
    {
        $el = Set::fromDER($data);
        $this->assertInstanceOf(Set::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        $this->assertEquals($ref, $el);
    }

    /**
     * @test
     */
    public function sortSame()
    {
        $set = new Set(new NullType(), new NullType());
        $sorted = $set->sortedSet();
        $this->assertEquals($set, $sorted);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(Set::class, $wrap->asSet());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('SET expected, got primitive NULL');
        $wrap->asSet();
    }
}
