<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class SubjectAlternativeNameTest extends RefExtTestHelper
{
    /**
     * @return SubjectAlternativeNameExtension
     *
     * @test
     */
    public function subjectAlternativeName()
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_ALT_NAME);
        static::assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends subjectAlternativeName
     *
     * @test
     */
    public function sANEmail(SubjectAlternativeNameExtension $san)
    {
        $email = $san->names()
            ->firstOf(GeneralName::TAG_RFC822_NAME)
            ->email();
        static::assertEquals('foo@example.com', $email);
    }

    /**
     * @depends subjectAlternativeName
     *
     * @test
     */
    public function sANURI(SubjectAlternativeNameExtension $san)
    {
        $uri = $san->names()
            ->firstOf(GeneralName::TAG_URI)
            ->uri();
        static::assertEquals('urn:foo:bar', $uri);
    }

    /**
     * @depends subjectAlternativeName
     *
     * @test
     */
    public function sANDNS(SubjectAlternativeNameExtension $san)
    {
        $name = $san->names()
            ->firstOf(GeneralName::TAG_DNS_NAME)
            ->name();
        static::assertEquals('alt.example.com', $name);
    }

    /**
     * @depends subjectAlternativeName
     *
     * @test
     */
    public function sANRegisteredID(SubjectAlternativeNameExtension $san)
    {
        $oid = $san->names()
            ->firstOf(GeneralName::TAG_REGISTERED_ID)
            ->oid();
        static::assertEquals('1.3.6.1.4.1.45710.2.1', $oid);
    }

    /**
     * @depends subjectAlternativeName
     *
     * @test
     */
    public function sANIPAddresses(SubjectAlternativeNameExtension $san)
    {
        $names = $san->names()
            ->allOf(GeneralName::TAG_IP_ADDRESS);
        $ips = array_map(fn ($name) => $name->address(), $names);
        static::assertEqualsCanonicalizing(['127.0.0.1', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'], $ips);
    }

    /**
     * @depends subjectAlternativeName
     *
     * @test
     */
    public function sANDirectoryName(SubjectAlternativeNameExtension $san)
    {
        $dn = $san->names()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        static::assertEquals('o=ACME Alternative Ltd.,c=FI,cn=alt.example.com', $dn);
    }
}
