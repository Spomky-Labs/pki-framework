<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @internal
 */
final class UserNoticeQualifierTest extends TestCase
{
    #[Test]
    public function create(): UserNoticeQualifier
    {
        $qual = UserNoticeQualifier::create(
            DisplayText::fromString('test'),
            NoticeReference::create(DisplayText::fromString('org'), 1, 2, 3)
        );
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('create')]
    public function encode(UserNoticeQualifier $qual): string
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
    public function decode($data): UserNoticeQualifier
    {
        $qual = UserNoticeQualifier::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(UserNoticeQualifier $ref, UserNoticeQualifier $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function explicitText(UserNoticeQualifier $qual)
    {
        static::assertInstanceOf(DisplayText::class, $qual->explicitText());
    }

    #[Test]
    #[Depends('create')]
    public function noticeRef(UserNoticeQualifier $qual)
    {
        static::assertInstanceOf(NoticeReference::class, $qual->noticeRef());
    }

    #[Test]
    public function createEmpty()
    {
        $qual = UserNoticeQualifier::create();
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('createEmpty')]
    public function explicitTextFail(UserNoticeQualifier $qual)
    {
        $this->expectException(LogicException::class);
        $qual->explicitText();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noticeRefFail(UserNoticeQualifier $qual)
    {
        $this->expectException(LogicException::class);
        $qual->noticeRef();
    }
}
