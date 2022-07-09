<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\DirectoryString;

class AttributeCollectionCastTestAttrValue extends DirectoryString
{
    public function __construct(string $str)
    {
        $this->_oid = '1.3.6.1.3';
        parent::__construct($str, self::UTF8);
    }
}
