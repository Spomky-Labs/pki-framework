<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Value;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\DirectoryString;
use UnexpectedValueException;

/**
 * @internal
 */
final class DirectoryStringTest extends TestCase
{
    #[Test]
    public function fromASN1InvalidType()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Type NULL is not valid DirectoryString');
        DirectoryString::fromASN1(UnspecifiedType::create(NullType::create()));
    }

    #[Test]
    public function toASN1InvalidType()
    {
        $value = CommonNameValue::create('name', Element::TYPE_NULL);
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Type NULL is not valid DirectoryString');
        $value->toASN1();
    }

    #[Test]
    public function teletexValue()
    {
        $value = CommonNameValue::create('name', Element::TYPE_T61_STRING);
        static::assertSame('#1404' . bin2hex('name'), $value->rfc2253String());
    }
}
