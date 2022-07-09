<?php

declare(strict_types=1);

namespace unit\certificate\extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use Sop\X509\Certificate\Extension\PolicyMappingsExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class PolicyMappingsTest extends TestCase
{
    const ISSUER_POLICY_OID = '1.3.6.1.3.1';

    const SUBJECT_POLICY_OID = '1.3.6.1.3.2';

    public function testCreateMappings()
    {
        $mappings = [
            new PolicyMapping(self::ISSUER_POLICY_OID, self::SUBJECT_POLICY_OID),
            new PolicyMapping('1.3.6.1.3.3', '1.3.6.1.3.4'),];
        $this->assertInstanceOf(PolicyMapping::class, $mappings[0]);
        return $mappings;
    }

    /**
     * @depends testCreateMappings
     *
     * @param array $mappings
     */
    public function testCreate(array $mappings)
    {
        $ext = new PolicyMappingsExtension(true, ...$mappings);
        $this->assertInstanceOf(PolicyMappingsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_POLICY_MAPPINGS, $ext->oid());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testEncode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ext = PolicyMappingsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(PolicyMappingsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Extension $ref
     * @param Extension $new
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testMappings(PolicyMappingsExtension $ext)
    {
        $this->assertContainsOnlyInstancesOf(PolicyMapping::class,
            $ext->mappings());
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testIssuerMappings(PolicyMappingsExtension $ext)
    {
        $this->assertContainsOnly('string',
            $ext->issuerMappings(self::ISSUER_POLICY_OID));
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testCount(PolicyMappingsExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testIterator(PolicyMappingsExtension $ext)
    {
        $values = [];
        foreach ($ext as $mapping) {
            $values[] = $mapping;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(PolicyMapping::class, $values);
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testMapping(PolicyMappingsExtension $ext)
    {
        $mapping = $ext->mappings()[0];
        $this->assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    /**
     * @depends testMapping
     *
     * @param PolicyMapping $mapping
     */
    public function testIssuerPolicy(PolicyMapping $mapping)
    {
        $this->assertEquals(self::ISSUER_POLICY_OID,
            $mapping->issuerDomainPolicy());
    }

    /**
     * @depends testMapping
     *
     * @param PolicyMapping $mapping
     */
    public function testSubjectPolicy(PolicyMapping $mapping)
    {
        $this->assertEquals(self::SUBJECT_POLICY_OID,
            $mapping->subjectDomainPolicy());
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testHasAnyPolicyMapping(PolicyMappingsExtension $ext)
    {
        $this->assertFalse($ext->hasAnyPolicyMapping());
    }

    public function testHasAnyPolicyIssuer()
    {
        $ext = new PolicyMappingsExtension(false,
            new PolicyMapping(PolicyInformation::OID_ANY_POLICY,
                self::SUBJECT_POLICY_OID));
        $this->assertTrue($ext->hasAnyPolicyMapping());
    }

    public function testHasAnyPolicySubject()
    {
        $ext = new PolicyMappingsExtension(false,
            new PolicyMapping(self::ISSUER_POLICY_OID,
                PolicyInformation::OID_ANY_POLICY));
        $this->assertTrue($ext->hasAnyPolicyMapping());
    }

    /**
     * @depends testCreate
     *
     * @param PolicyMappingsExtension $ext
     */
    public function testExtensions(PolicyMappingsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasPolicyMappings());
        return $extensions;
    }

    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->policyMappings();
        $this->assertInstanceOf(PolicyMappingsExtension::class, $ext);
    }

    public function testEncodeEmptyFail()
    {
        $ext = new PolicyMappingsExtension(false);
        $this->expectException(\LogicException::class);
        $ext->toASN1();
    }

    public function testDecodeEmptyFail()
    {
        $seq = new Sequence();
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_POLICY_MAPPINGS),
            new OctetString($seq->toDER()));
        $this->expectException(\UnexpectedValueException::class);
        PolicyMappingsExtension::fromASN1($ext_seq);
    }
}
