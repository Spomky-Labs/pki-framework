<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC;

use function array_key_exists;
use function in_array;
use InvalidArgumentException;
use LogicException;
use function mb_strlen;
use function ord;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use UnexpectedValueException;

/**
 * Implements elliptic curve public key type as specified by RFC 5480.
 *
 * @see https://tools.ietf.org/html/rfc5480#section-2.2
 */
final class ECPublicKey extends PublicKey
{
    /**
     * Elliptic curve public key.
     */
    protected string $_ecPoint;

    /**
     * @param string $ec_point ECPoint
     * @param null|string $_namedCurve Named curve OID
     */
    public function __construct(
        string $ec_point,
        protected ?string $_namedCurve = null
    ) {
        // first octet must be 0x04 for uncompressed form, and 0x02 or 0x03
        // for compressed form.
        if (! mb_strlen($ec_point, '8bit') || ! in_array(ord($ec_point[0]), [2, 3, 4], true)) {
            throw new InvalidArgumentException('Invalid ECPoint.');
        }
        $this->_ecPoint = $ec_point;
    }

    /**
     * Initialize from curve point coordinates.
     *
     * @param int|string $x X coordinate as a base10 number
     * @param int|string $y Y coordinate as a base10 number
     * @param null|string $named_curve Named curve OID
     * @param null|int $bits Size of *p* in bits
     */
    public static function fromCoordinates(
        int|string $x,
        int|string $y,
        ?string $named_curve = null,
        ?int $bits = null
    ): self {
        // if bitsize is not explicitly set, check from supported curves
        if (! isset($bits) && isset($named_curve)) {
            $bits = self::_curveSize($named_curve);
        }
        $mlen = null;
        if (isset($bits)) {
            $mlen = (int) ceil($bits / 8);
        }
        $x_os = ECConversion::integerToOctetString(new Integer($x), $mlen)->string();
        $y_os = ECConversion::integerToOctetString(new Integer($y), $mlen)->string();
        $ec_point = "\x4{$x_os}{$y_os}";
        return new self($ec_point, $named_curve);
    }

    /**
     * @see PublicKey::fromPEM()
     */
    public static function fromPEM(PEM $pem): self
    {
        if ($pem->type() !== PEM::TYPE_PUBLIC_KEY) {
            throw new UnexpectedValueException('Not a public key.');
        }
        $pki = PublicKeyInfo::fromDER($pem->data());
        $algo = $pki->algorithmIdentifier();
        if ($algo->oid() !== AlgorithmIdentifier::OID_EC_PUBLIC_KEY
            || ! ($algo instanceof ECPublicKeyAlgorithmIdentifier)) {
            throw new UnexpectedValueException('Not an elliptic curve key.');
        }
        // ECPoint is directly mapped into public key data
        return new self($pki->publicKeyData()->string(), $algo->namedCurve());
    }

    /**
     * Get ECPoint value.
     */
    public function ECPoint(): string
    {
        return $this->_ecPoint;
    }

    /**
     * Get curve point coordinates.
     *
     * @return string[] Tuple of X and Y coordinates as base-10 numbers
     */
    public function curvePoint(): array
    {
        return array_map(fn ($str) => ECConversion::octetsToNumber($str), $this->curvePointOctets());
    }

    /**
     * Get curve point coordinates in octet string representation.
     *
     * @return string[] tuple of X and Y field elements as a string
     */
    public function curvePointOctets(): array
    {
        if ($this->isCompressed()) {
            throw new RuntimeException('EC point compression not supported.');
        }
        $str = mb_substr($this->_ecPoint, 1, null, '8bit');
        [$x, $y] = mb_str_split($str, (int) floor(mb_strlen($str, '8bit') / 2), '8bit');
        return [$x, $y];
    }

    /**
     * Whether ECPoint is in compressed form.
     */
    public function isCompressed(): bool
    {
        $c = ord($this->_ecPoint[0]);
        return $c !== 4;
    }

    /**
     * Whether named curve is present.
     */
    public function hasNamedCurve(): bool
    {
        return isset($this->_namedCurve);
    }

    /**
     * Get named curve OID.
     */
    public function namedCurve(): string
    {
        if (! $this->hasNamedCurve()) {
            throw new LogicException('namedCurve not set.');
        }
        return $this->_namedCurve;
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new ECPublicKeyAlgorithmIdentifier($this->namedCurve());
    }

    /**
     * Generate ASN.1 element.
     */
    public function toASN1(): OctetString
    {
        return new OctetString($this->_ecPoint);
    }

    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }

    /**
     * @see https://tools.ietf.org/html/rfc5480#section-2.2
     */
    public function subjectPublicKey(): BitString
    {
        // ECPoint is directly mapped to subjectPublicKey
        return new BitString($this->_ecPoint);
    }

    /**
     * Get the curve size *p* in bits.
     *
     * @param string $oid Curve OID
     */
    private static function _curveSize(string $oid): ?int
    {
        if (! array_key_exists($oid, ECPublicKeyAlgorithmIdentifier::MAP_CURVE_TO_SIZE)) {
            return null;
        }
        return ECPublicKeyAlgorithmIdentifier::MAP_CURVE_TO_SIZE[$oid];
    }
}
