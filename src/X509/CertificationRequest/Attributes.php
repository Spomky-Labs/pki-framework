<?php

declare(strict_types=1);

namespace Sop\X509\CertificationRequest;

use LogicException;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\Collection\SetOfAttributes;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;

/**
 * Implements *Attributes* ASN.1 type of *CertificationRequestInfo*.
 *
 * @see https://tools.ietf.org/html/rfc2986#section-4
 */
final class Attributes extends SetOfAttributes
{
    /**
     * Mapping from OID to attribute value class name.
     *
     * @internal
     *
     * @var array
     */
    final public const MAP_OID_TO_CLASS = [
        ExtensionRequestValue::OID => ExtensionRequestValue::class,
    ];

    /**
     * Check whether extension request attribute is present.
     */
    public function hasExtensionRequest(): bool
    {
        return $this->has(ExtensionRequestValue::OID);
    }

    /**
     * Get extension request attribute value.
     */
    public function extensionRequest(): ExtensionRequestValue
    {
        if (! $this->hasExtensionRequest()) {
            throw new LogicException('No extension request attribute.');
        }
        return $this->firstOf(ExtensionRequestValue::OID)->first();
    }

    protected static function _castAttributeValues(Attribute $attribute): Attribute
    {
        $oid = $attribute->oid();
        if (isset(self::MAP_OID_TO_CLASS[$oid])) {
            return $attribute->castValues(self::MAP_OID_TO_CLASS[$oid]);
        }
        return $attribute;
    }
}
