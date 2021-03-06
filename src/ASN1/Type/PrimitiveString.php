<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type;

use function assert;
use InvalidArgumentException;
use function is_string;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;

/**
 * Base class for primitive strings.
 *
 * Used by types that don't require special processing of the encoded string data.
 *
 * @internal
 */
abstract class PrimitiveString extends BaseString
{
    use PrimitiveType;

    protected function encodedAsDER(): string
    {
        return $this->_string;
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        if (! $identifier->isPrimitive()) {
            throw new DecodeException('DER encoded string must be primitive.');
        }
        $length = Length::expectFromDER($data, $idx)->intLength();
        $str = $length ? mb_substr($data, $idx, $length, '8bit') : '';
        // substr should never return false, since length is
        // checked by Length::expectFromDER.
        assert(is_string($str), new DecodeException('substr'));
        $offset = $idx + $length;
        try {
            return new static($str);
        } catch (InvalidArgumentException $e) {
            throw new DecodeException($e->getMessage(), 0, $e);
        }
    }
}
