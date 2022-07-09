<?php

declare(strict_types = 1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *uniformResourceIdentifier* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class UniformResourceIdentifier extends GeneralName
{
    /**
     * URI.
     *
     * @var string
     */
    protected $_uri;

    /**
     * Constructor.
     *
     * @param string $uri
     */
    public function __construct(string $uri)
    {
        $this->_tag = self::TAG_URI;
        $this->_uri = $uri;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        return new self($el->asIA5String()->string());
    }

    /**
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_uri;
    }

    /**
     * Get URI.
     *
     * @return string
     */
    public function uri(): string
    {
        return $this->_uri;
    }

    /**
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_uri));
    }
}
