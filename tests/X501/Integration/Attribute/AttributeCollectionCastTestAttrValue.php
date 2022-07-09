<?php

declare(strict_types=1);

namespace Sop\Test\X501\Integration\Attribute;

use Sop\X501\ASN1\AttributeValue\Feature\DirectoryString;

class AttributeCollectionCastTestAttrValue extends DirectoryString
{
    public function __construct(string $str)
    {
        $this->_oid = '1.3.6.1.3';
        parent::__construct($str, self::UTF8);
    }
}
