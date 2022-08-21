<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
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

    /**
     * @test
     */
    public function createMappings()
    {
        $mappings = [
            PolicyMapping::create(self::ISSUER_POLICY_OID, self::SUBJECT_POLICY_OID),
            PolicyMapping::create('1.3.6.1.3.3', '1.3.6.1.3.4'), ];
        static::assertInstanceOf(PolicyMapping::class, $mappings[0]);
        return $mappings;
    }

    /**
     * @depends createMappings
     *
     * @test
     */
    public function create(array $mappings)
    {
        $ext = new PolicyMappingsExtension(true, ...$mappings);
        static::assertInstanceOf(PolicyMappingsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_POLICY_MAPPINGS, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
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
        $ext = PolicyMappingsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(PolicyMappingsExtension::class, $ext);
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
    public function mappings(PolicyMappingsExtension $ext)
    {
        static::assertContainsOnlyInstancesOf(PolicyMapping::class, $ext->mappings());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function issuerMappings(PolicyMappingsExtension $ext)
    {
        static::assertContainsOnly('string', $ext->issuerMappings(self::ISSUER_POLICY_OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(PolicyMappingsExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(PolicyMappingsExtension $ext)
    {
        $values = [];
        foreach ($ext as $mapping) {
            $values[] = $mapping;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(PolicyMapping::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function mapping(PolicyMappingsExtension $ext)
    {
        $mapping = $ext->mappings()[0];
        static::assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    /**
     * @depends mapping
     *
     * @test
     */
    public function issuerPolicy(PolicyMapping $mapping)
    {
        static::assertEquals(self::ISSUER_POLICY_OID, $mapping->issuerDomainPolicy());
    }

    /**
     * @depends mapping
     *
     * @test
     */
    public function subjectPolicy(PolicyMapping $mapping)
    {
        static::assertEquals(self::SUBJECT_POLICY_OID, $mapping->subjectDomainPolicy());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasAnyPolicyMapping(PolicyMappingsExtension $ext)
    {
        static::assertFalse($ext->hasAnyPolicyMapping());
    }

    /**
     * @test
     */
    public function hasAnyPolicyIssuer()
    {
        $ext = new PolicyMappingsExtension(
            false,
            PolicyMapping::create(PolicyInformation::OID_ANY_POLICY, self::SUBJECT_POLICY_OID)
        );
        static::assertTrue($ext->hasAnyPolicyMapping());
    }

    /**
     * @test
     */
    public function hasAnyPolicySubject()
    {
        $ext = new PolicyMappingsExtension(
            false,
            PolicyMapping::create(self::ISSUER_POLICY_OID, PolicyInformation::OID_ANY_POLICY)
        );
        static::assertTrue($ext->hasAnyPolicyMapping());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(PolicyMappingsExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasPolicyMappings());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->policyMappings();
        static::assertInstanceOf(PolicyMappingsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $ext = new PolicyMappingsExtension(false);
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
            ObjectIdentifier::create(Extension::OID_POLICY_MAPPINGS),
            OctetString::create($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        PolicyMappingsExtension::fromASN1($ext_seq);
    }
}
