<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappingsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use UnexpectedValueException;

/**
 * @internal
 */
final class PolicyMappingsTest extends TestCase
{
    final public const ISSUER_POLICY_OID = '1.3.6.1.3.1';

    final public const SUBJECT_POLICY_OID = '1.3.6.1.3.2';

    #[Test]
    public function createMappings(): array
    {
        $mappings = [
            PolicyMapping::create(self::ISSUER_POLICY_OID, self::SUBJECT_POLICY_OID),
            PolicyMapping::create('1.3.6.1.3.3', '1.3.6.1.3.4'), ];
        static::assertInstanceOf(PolicyMapping::class, $mappings[0]);
        return $mappings;
    }

    #[Test]
    #[Depends('createMappings')]
    public function create(array $mappings): PolicyMappingsExtension
    {
        $ext = PolicyMappingsExtension::create(true, ...$mappings);
        static::assertInstanceOf(PolicyMappingsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_POLICY_MAPPINGS, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $ext = PolicyMappingsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(PolicyMappingsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function mappings(PolicyMappingsExtension $ext)
    {
        static::assertContainsOnlyInstancesOf(PolicyMapping::class, $ext->mappings());
    }

    #[Test]
    #[Depends('create')]
    public function issuerMappings(PolicyMappingsExtension $ext)
    {
        static::assertContainsOnly('string', $ext->issuerMappings(self::ISSUER_POLICY_OID));
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(PolicyMappingsExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(PolicyMappingsExtension $ext)
    {
        $values = [];
        foreach ($ext as $mapping) {
            $values[] = $mapping;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(PolicyMapping::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function mapping(PolicyMappingsExtension $ext)
    {
        $mapping = $ext->mappings()[0];
        static::assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    #[Test]
    #[Depends('mapping')]
    public function issuerPolicy(PolicyMapping $mapping)
    {
        static::assertSame(self::ISSUER_POLICY_OID, $mapping->issuerDomainPolicy());
    }

    #[Test]
    #[Depends('mapping')]
    public function subjectPolicy(PolicyMapping $mapping)
    {
        static::assertSame(self::SUBJECT_POLICY_OID, $mapping->subjectDomainPolicy());
    }

    #[Test]
    #[Depends('create')]
    public function hasAnyPolicyMapping(PolicyMappingsExtension $ext)
    {
        static::assertFalse($ext->hasAnyPolicyMapping());
    }

    #[Test]
    public function hasAnyPolicyIssuer()
    {
        $ext = PolicyMappingsExtension::create(
            false,
            PolicyMapping::create(PolicyInformation::OID_ANY_POLICY, self::SUBJECT_POLICY_OID)
        );
        static::assertTrue($ext->hasAnyPolicyMapping());
    }

    #[Test]
    public function hasAnyPolicySubject()
    {
        $ext = PolicyMappingsExtension::create(
            false,
            PolicyMapping::create(self::ISSUER_POLICY_OID, PolicyInformation::OID_ANY_POLICY)
        );
        static::assertTrue($ext->hasAnyPolicyMapping());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(PolicyMappingsExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasPolicyMappings());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->policyMappings();
        static::assertInstanceOf(PolicyMappingsExtension::class, $ext);
    }

    #[Test]
    public function encodeEmptyFail()
    {
        $ext = PolicyMappingsExtension::create(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    #[Test]
    public function decodeEmptyFail()
    {
        $seq = Sequence::create();
        $ext_seq = Sequence::create(
            ObjectIdentifier::create(Extension::OID_POLICY_MAPPINGS),
            OctetString::create($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        PolicyMappingsExtension::fromASN1($ext_seq);
    }
}
