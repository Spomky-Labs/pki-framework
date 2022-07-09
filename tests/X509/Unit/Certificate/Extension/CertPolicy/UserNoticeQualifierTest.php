<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\CertPolicy;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use Sop\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @internal
 */
final class UserNoticeQualifierTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $qual = new UserNoticeQualifier(
            DisplayText::fromString('test'),
            new NoticeReference(DisplayText::fromString('org'), 1, 2, 3)
        );
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(UserNoticeQualifier $qual)
    {
        $el = $qual->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $qual = UserNoticeQualifier::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(UserNoticeQualifier $ref, UserNoticeQualifier $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function explicitText(UserNoticeQualifier $qual)
    {
        static::assertInstanceOf(DisplayText::class, $qual->explicitText());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noticeRef(UserNoticeQualifier $qual)
    {
        static::assertInstanceOf(NoticeReference::class, $qual->noticeRef());
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $qual = new UserNoticeQualifier();
        static::assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function explicitTextFail(UserNoticeQualifier $qual)
    {
        $this->expectException(LogicException::class);
        $qual->explicitText();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noticeRefFail(UserNoticeQualifier $qual)
    {
        $this->expectException(LogicException::class);
        $qual->noticeRef();
    }
}
