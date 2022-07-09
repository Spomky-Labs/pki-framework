<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Eoc;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\EOC;

/**
 * @internal
 */
final class EOCTest extends TestCase
{
    /**
     * @test
     */
    public function create(): Element
    {
        $el = new EOC();
        $this->assertInstanceOf(EOC::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_EOC, $el->tag());
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
     * @param string $data
     *
     * @test
     */
    public function decode($data): EOC
    {
        $el = EOC::fromDER($data);
        $this->assertInstanceOf(EOC::class, $el);
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
}
