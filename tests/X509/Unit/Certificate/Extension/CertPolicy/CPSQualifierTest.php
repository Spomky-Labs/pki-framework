<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;

/**
 * @internal
 */
final class CPSQualifierTest extends TestCase
{
    public const URI = 'urn:test';

    #[Test]
    public function create(): CPSQualifier
    {
        $qual = CPSQualifier::create(self::URI);
        static::assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('create')]
    public function encode(CPSQualifier $qual): string
    {
        $el = $qual->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): CPSQualifier
    {
        $qual = CPSQualifier::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(CPSQualifier $ref, CPSQualifier $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function uRI(CPSQualifier $qual)
    {
        static::assertSame(self::URI, $qual->uri());
    }

    #[Test]
    #[Depends('create')]
    public function oID(CPSQualifier $qual)
    {
        static::assertSame(CPSQualifier::OID_CPS, $qual->oid());
    }
}
