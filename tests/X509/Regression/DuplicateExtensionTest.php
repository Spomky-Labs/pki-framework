<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class DuplicateExtensionTest extends TestCase
{
    #[Test]
    public function duplicateExtensionIsRejected(): void
    {
        // Before the fix the second basicConstraints silently overwrote the first, so a certificate carrying
        // CA:FALSE followed by CA:TRUE was read as a CA certificate with no warning at all.
        $seq = Sequence::create(
            BasicConstraintsExtension::create(true, false)->toASN1(),
            BasicConstraintsExtension::create(true, true)->toASN1(),
        );

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('2.5.29.19 occurs more than once');
        Extensions::fromASN1($seq);
    }

    #[Test]
    public function duplicateIsRejectedRegardlessOfPosition(): void
    {
        $seq = Sequence::create(
            BasicConstraintsExtension::create(true, true)->toASN1(),
            KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE)->toASN1(),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN)->toASN1(),
        );

        $this->expectException(UnexpectedValueException::class);
        Extensions::fromASN1($seq);
    }

    #[Test]
    public function distinctExtensionsAreStillAccepted(): void
    {
        $seq = Sequence::create(
            BasicConstraintsExtension::create(true, true)->toASN1(),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN)->toASN1(),
        );

        static::assertCount(2, Extensions::fromASN1($seq));
    }

    #[Test]
    public function duplicateIsRejectedInACsrExtensionRequest(): void
    {
        // The CSR extensionRequest is attacker supplied, and it decodes through the very same Extensions::fromASN1(),
        // so the duplicate cannot slip past an inspection that walks the decoded request either.
        $seq = Sequence::create(
            BasicConstraintsExtension::create(true, false)->toASN1(),
            BasicConstraintsExtension::create(true, true)->toASN1(),
        );

        $this->expectException(UnexpectedValueException::class);
        ExtensionRequestValue::fromASN1($seq->asUnspecified());
    }

    #[Test]
    public function duplicateIsRejectedInAnAttributeCertificate(): void
    {
        $acinfo = AttributeCertificateInfo::create(
            Holder::create(IssuerSerial::create(GeneralNames::create(DirectoryName::fromDNString('cn=Issuer')), '42')),
            AttCertIssuer::fromName(Name::fromString('cn=Issuer')),
            AttCertValidityPeriod::fromStrings('2026-01-01 12:00:00', '2026-01-01 13:00:00'),
            Attributes::fromAttributeValues(RoleAttributeValue::create(UniformResourceIdentifier::create('urn:admin')))
        )
            ->withSignature(SHA256WithRSAEncryptionAlgorithmIdentifier::create())
            ->withSerialNumber(1);

        // Append an extensions SEQUENCE carrying the same OID twice to the encoded acinfo.
        $elements = array_map(
            static fn (UnspecifiedType $el) => $el->asElement(),
            $acinfo->toASN1()
                ->elements()
        );
        $elements[] = Sequence::create(
            BasicConstraintsExtension::create(true, false)->toASN1(),
            BasicConstraintsExtension::create(true, true)->toASN1(),
        );

        $this->expectException(UnexpectedValueException::class);
        AttributeCertificateInfo::fromASN1(Sequence::create(...$elements));
    }

    #[Test]
    public function constructionApiKeepsLastWinsSemantics(): void
    {
        // withExtensions() builds a certificate rather than decoding untrusted input, so overriding an
        // extension by OID stays intentional there.
        $extensions = Extensions::create(BasicConstraintsExtension::create(true, false))
            ->withExtensions(BasicConstraintsExtension::create(true, true));

        static::assertTrue($extensions->basicConstraints()->isCA());
        static::assertCount(1, $extensions);
    }
}
