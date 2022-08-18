<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use BadMethodCallException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;

/**
 * Class to park payload of an unknown extension.
 */
final class UnknownExtension extends Extension
{
    /**
     * Raw extension value.
     */
    protected string $_data;

    public function __construct(
        string $oid,
        bool $critical,
        protected Element $_element
    ) {
        parent::__construct($oid, $critical);
        $this->_data = $_element->toDER();
    }

    /**
     * Create instance from a raw encoded extension value.
     */
    public static function fromRawString(string $oid, bool $critical, string $data): self
    {
        $obj = new self($oid, $critical, OctetString::create(''));
        $obj->_element = NullType::create();
        $obj->_data = $data;
        return $obj;
    }

    /**
     * Get the encoded extension value.
     */
    public function extensionValue(): string
    {
        return $this->_data;
    }

    protected function _extnValue(): OctetString
    {
        return OctetString::create($this->_data);
    }

    protected function _valueASN1(): Element
    {
        return $this->_element;
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }
}
