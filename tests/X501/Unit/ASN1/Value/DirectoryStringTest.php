<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1\Value;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\Feature\DirectoryString;
use UnexpectedValueException;

/**
 * @internal
 */
final class DirectoryStringTest extends TestCase
{
    public function testFromASN1InvalidType()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Type NULL is not valid DirectoryString');
        DirectoryString::fromASN1(new UnspecifiedType(new NullType()));
    }

    public function testToASN1InvalidType()
    {
        $value = new CommonNameValue('name', Element::TYPE_NULL);
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Type NULL is not valid DirectoryString');
        $value->toASN1();
    }

    public function testTeletexValue()
    {
        $value = new CommonNameValue('name', Element::TYPE_T61_STRING);
        $this->assertEquals('#1404' . bin2hex('name'), $value->rfc2253String());
    }
}
