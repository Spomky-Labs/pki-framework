<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class PolicyQualifierInfoTest extends TestCase
{
    #[Test]
    public function fromASN1UnknownTypeFail()
    {
        $seq = Sequence::create(ObjectIdentifier::create('1.3.6.1.3'), NullType::create());
        $this->expectException(UnexpectedValueException::class);
        PolicyQualifierInfo::fromASN1($seq);
    }
}
