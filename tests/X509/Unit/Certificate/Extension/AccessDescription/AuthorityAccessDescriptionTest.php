<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\AccessDescription;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AuthorityAccessDescriptionTest extends TestCase
{
    public const URI = 'urn:test';

    #[Test]
    public function create(): AuthorityAccessDescription
    {
        $desc = AuthorityAccessDescription::create(
            AuthorityAccessDescription::OID_METHOD_OSCP,
            UniformResourceIdentifier::create(self::URI)
        );
        static::assertInstanceOf(AuthorityAccessDescription::class, $desc);
        return $desc;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AuthorityAccessDescription $desc): string
    {
        $el = $desc->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): AuthorityAccessDescription
    {
        $desc = AuthorityAccessDescription::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(AuthorityAccessDescription::class, $desc);
        return $desc;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AuthorityAccessDescription $ref, AuthorityAccessDescription $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function isOSCP(AuthorityAccessDescription $desc)
    {
        static::assertTrue($desc->isOSCPMethod());
    }

    #[Test]
    #[Depends('create')]
    public function isNotCAIssuers(AuthorityAccessDescription $desc)
    {
        static::assertFalse($desc->isCAIssuersMethod());
    }

    #[Test]
    #[Depends('create')]
    public function accessMethod(AuthorityAccessDescription $desc)
    {
        static::assertSame(AuthorityAccessDescription::OID_METHOD_OSCP, $desc->accessMethod());
    }

    #[Test]
    #[Depends('create')]
    public function location(AuthorityAccessDescription $desc)
    {
        static::assertSame(self::URI, $desc->accessLocation()->string());
    }
}
