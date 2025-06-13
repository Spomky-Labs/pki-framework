<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Certificate;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * @internal
 */
final class CertificateValidationTest extends TestCase
{
    #[Test]
    #[DataProvider('selfSignedCertificates')]
    public function validateSelfSignedCertificate(string $pemCertificateFilename)
    {
        $certificate = Certificate::fromPEM(PEM::fromFile($pemCertificateFilename));
        $spki = $certificate->tbsCertificate()
            ->subjectPublicKeyInfo();
        static::assertTrue($certificate->verify($spki));
    }

    public static function selfSignedCertificates(): Iterator
    {
        $certsAssertDir = __DIR__ . '/../../../assets/certs/';
        yield 'acme-ca' => [$certsAssertDir . '/acme-ca.pem'];
        yield 'feitian-ca' => [$certsAssertDir . '/feitian-ca.pem'];
    }
}
