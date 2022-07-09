<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use UnexpectedValueException;

/*
From RFC 8410:

    For all of the OIDs, the parameters MUST be absent.

    It is possible to find systems that require the parameters to be
    present.  This can be due to either a defect in the original 1997
    syntax or a programming error where developers never got input where
    this was not true.  The optimal solution is to fix these systems;
    where this is not possible, the problem needs to be restricted to
    that subsystem and not propagated to the Internet.
*/

/**
 * Algorithm identifier for the Edwards-curve Digital Signature Algorithm (EdDSA) identifiers specified by RFC 8410.
 *
 * Same algorithm identifier is used for public and private keys as well as for signatures.
 *
 * @see https://tools.ietf.org/html/rfc8410#section-3
 * @see https://tools.ietf.org/html/rfc8410#section-6
 */
abstract class RFC8410EdAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements AsymmetricCryptoAlgorithmIdentifier, SignatureAlgorithmIdentifier
{
    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (isset($params)) {
            throw new UnexpectedValueException('Parameters must be absent.');
        }
        return new static();
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
