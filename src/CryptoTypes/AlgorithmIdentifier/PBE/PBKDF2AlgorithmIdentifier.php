<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE;

use const PHP_INT_MAX;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use function sprintf;
use UnexpectedValueException;

/*
 * From RFC 8018 - A.2. PBKDF2:
 *
 * PBKDF2-params ::= SEQUENCE {
 *     salt CHOICE {
 *         specified OCTET STRING,
 *         otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
 *     },
 *     iterationCount INTEGER (1..MAX),
 *     keyLength INTEGER (1..MAX) OPTIONAL,
 *     prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
 * }
 */

/**
 * Algorithm identifier for the PBKDF2 key derivation function.
 *
 * The pseudorandom function is kept as whatever algorithm identifier the parameters name, so that a structure with
 * a function this library cannot compute still parses and re-encodes; whether it can be used is decided when a key
 * is derived.
 *
 * @see https://tools.ietf.org/html/rfc8018#section-5.2
 * @see https://tools.ietf.org/html/rfc8018#appendix-A.2
 */
final class PBKDF2AlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
    /**
     * @param positive-int $iterationCount
     * @param null|positive-int $keyLength
     */
    private function __construct(
        private readonly string $salt,
        private readonly int $iterationCount,
        private readonly ?int $keyLength,
        private readonly AlgorithmIdentifierType $prf
    ) {
        parent::__construct(self::OID_PBKDF2);
    }

    /**
     * @param string $salt Salt, at least 8 bytes per RFC 8018 sect. 4.1
     * @param null|int $keyLength Length of the derived key in bytes, if it is to be stated
     * @param null|AlgorithmIdentifierType $prf Pseudorandom function, hmacWithSHA1 by default
     */
    public static function create(
        string $salt,
        int $iterationCount,
        ?int $keyLength = null,
        ?AlgorithmIdentifierType $prf = null
    ): self {
        if ($iterationCount < 1) {
            throw new UnexpectedValueException('PBKDF2 iteration count must be positive.');
        }
        if ($keyLength !== null && $keyLength < 1) {
            throw new UnexpectedValueException('PBKDF2 key length must be positive.');
        }
        return new self($salt, $iterationCount, $keyLength, $prf ?? HMACWithSHA1AlgorithmIdentifier::create());
    }

    public function name(): string
    {
        return 'PBKDF2';
    }

    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (! isset($params)) {
            throw new UnexpectedValueException('No parameters.');
        }
        $seq = $params->asSequence();
        if (! $seq->has(0, Element::TYPE_OCTET_STRING)) {
            throw new UnexpectedValueException('PBKDF2 salt from an otherSource algorithm is not supported.');
        }
        $salt = $seq->at(0)
            ->asOctetString()
            ->string();
        $iterationCount = self::positiveInt($seq->at(1)->asInteger(), 'iteration count');
        $idx = 2;
        $keyLength = null;
        if ($seq->has($idx, Element::TYPE_INTEGER)) {
            $keyLength = self::positiveInt($seq->at($idx++)->asInteger(), 'key length');
        }
        $prf = null;
        if ($seq->has($idx, Element::TYPE_SEQUENCE)) {
            $prf = self::prfFromASN1($seq->at($idx++)->asSequence());
        }
        if ($seq->has($idx)) {
            throw new UnexpectedValueException('Unexpected element in PBKDF2 parameters.');
        }
        return self::create($salt, $iterationCount, $keyLength, $prf);
    }

    public function salt(): string
    {
        return $this->salt;
    }

    /**
     * @return positive-int
     */
    public function iterationCount(): int
    {
        return $this->iterationCount;
    }

    /**
     * Get the stated length of the derived key in bytes, or null if the parameters leave it to the cipher.
     *
     * @return null|positive-int
     */
    public function keyLength(): ?int
    {
        return $this->keyLength;
    }

    /**
     * Get the pseudorandom function.
     */
    public function prf(): AlgorithmIdentifierType
    {
        return $this->prf;
    }

    protected function paramsASN1(): Sequence
    {
        $elements = [OctetString::create($this->salt), Integer::create($this->iterationCount)];
        if ($this->keyLength !== null) {
            $elements[] = Integer::create($this->keyLength);
        }
        // DER omits a component that equals its DEFAULT value (X.690 sect. 11.5)
        if ($this->prf->oid() !== self::OID_HMAC_WITH_SHA1) {
            $elements[] = $this->prf->toASN1();
        }
        return Sequence::create(...$elements);
    }

    /**
     * RFC 8018 gives hmacWithSHA1 NULL parameters, which the identifier of this library refuses since it follows
     * RFC 2898 in omitting them, so both forms are accepted here.
     */
    private static function prfFromASN1(Sequence $seq): AlgorithmIdentifierType
    {
        $oid = $seq->at(0)
            ->asObjectIdentifier()
            ->oid();
        if ($oid === self::OID_HMAC_WITH_SHA1) {
            if ($seq->has(1) && ! $seq->has(1, Element::TYPE_NULL)) {
                throw new UnexpectedValueException('Parameters of hmacWithSHA1 must be NULL or omitted.');
            }
            return HMACWithSHA1AlgorithmIdentifier::create();
        }
        return AlgorithmIdentifier::fromASN1($seq);
    }

    private static function positiveInt(Integer $number, string $what): int
    {
        $value = $number->getValue();
        if ($value->isLessThan(1) || $value->isGreaterThan(PHP_INT_MAX)) {
            throw new UnexpectedValueException(sprintf('PBKDF2 %s %s is out of range.', $what, $number->number()));
        }
        return $value->toInt();
    }
}
