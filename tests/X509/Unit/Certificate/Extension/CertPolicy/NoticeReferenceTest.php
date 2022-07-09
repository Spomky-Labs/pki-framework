<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\NoticeReference;

/**
 * @internal
 */
final class NoticeReferenceTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ref = new NoticeReference(DisplayText::fromString('org'), 1, 2, 3);
        static::assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(NoticeReference $ref)
    {
        $el = $ref->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
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
        $ref = NoticeReference::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(NoticeReference $ref, NoticeReference $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function organization(NoticeReference $ref)
    {
        static::assertEquals('org', $ref->organization() ->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function numbers(NoticeReference $ref)
    {
        static::assertEquals([1, 2, 3], $ref->numbers());
    }
}
