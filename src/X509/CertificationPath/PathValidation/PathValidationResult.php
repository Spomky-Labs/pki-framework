<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\CertificationPath\PathValidation;

use function count;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\CertificationPath\Policy\PolicyTree;

/**
 * Result of the path validation process.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.6
 */
final class PathValidationResult
{
    /**
     * Certificates in a certification path.
     *
     * @var Certificate[]
     */
    private readonly array $_certificates;

    /**
     * @param Certificate[] $certificates Certificates in a certification path
     * @param null|PolicyTree $_policyTree Valid policy tree
     * @param PublicKeyInfo $_publicKeyInfo Public key of the end-entity certificate
     * @param AlgorithmIdentifierType $_publicKeyAlgo Public key algorithm of the end-entity certificate
     * @param null|Element $_publicKeyParameters Algorithm parameters
     */
    public function __construct(
        array $certificates,
        protected ?PolicyTree $_policyTree,
        protected PublicKeyInfo $_publicKeyInfo,
        protected AlgorithmIdentifierType $_publicKeyAlgo,
        protected ?Element $_publicKeyParameters = null
    ) {
        $this->_certificates = array_values($certificates);
    }

    /**
     * Get end-entity certificate.
     */
    public function certificate(): Certificate
    {
        return $this->_certificates[count($this->_certificates) - 1];
    }

    /**
     * Get certificate policies of the end-entity certificate.
     *
     * @return PolicyInformation[]
     */
    public function policies(): array
    {
        if ($this->_policyTree === null) {
            return [];
        }
        return $this->_policyTree->policiesAtDepth(count($this->_certificates));
    }
}
