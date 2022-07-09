<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\CertificationPath\PathValidation;

use DateTimeImmutable;
use LogicException;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;

/**
 * Configuration for the certification path validation process.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.1
 */
final class PathValidationConfig
{
    /**
     * List of acceptable policy identifiers.
     *
     * @var string[]
     */
    private array $_policySet;

    /**
     * Trust anchor certificate.
     *
     * If not set, path validation uses the first certificate of the path.
     */
    private ?Certificate $_trustAnchor = null;

    /**
     * Whether policy mapping in inhibited.
     *
     * Setting this to true disallows policy mapping.
     */
    private bool $_policyMappingInhibit;

    /**
     * Whether the path must be valid for at least one policy in the initial policy set.
     */
    private bool $_explicitPolicy;

    /**
     * Whether anyPolicy OID processing should be inhibited.
     *
     * Setting this to true disallows the usage of anyPolicy.
     */
    private bool $_anyPolicyInhibit;

    /**
     * Constructor.
     *
     * @param DateTimeImmutable $_dateTime Reference date and time
     * @param int $_maxLength Maximum certification path length
     */
    public function __construct(
        protected DateTimeImmutable $_dateTime,
        protected int $_maxLength
    ) {
        $this->_policySet = [PolicyInformation::OID_ANY_POLICY];
        $this->_policyMappingInhibit = false;
        $this->_explicitPolicy = false;
        $this->_anyPolicyInhibit = false;
    }

    /**
     * Get default configuration.
     */
    public static function defaultConfig(): self
    {
        return new self(new DateTimeImmutable(), 3);
    }

    /**
     * Get self with maximum path length.
     */
    public function withMaxLength(int $length): self
    {
        $obj = clone $this;
        $obj->_maxLength = $length;
        return $obj;
    }

    /**
     * Get self with reference date and time.
     */
    public function withDateTime(DateTimeImmutable $dt): self
    {
        $obj = clone $this;
        $obj->_dateTime = $dt;
        return $obj;
    }

    /**
     * Get self with trust anchor certificate.
     */
    public function withTrustAnchor(Certificate $ca): self
    {
        $obj = clone $this;
        $obj->_trustAnchor = $ca;
        return $obj;
    }

    /**
     * Get self with initial-policy-mapping-inhibit set.
     */
    public function withPolicyMappingInhibit(bool $flag): self
    {
        $obj = clone $this;
        $obj->_policyMappingInhibit = $flag;
        return $obj;
    }

    /**
     * Get self with initial-explicit-policy set.
     */
    public function withExplicitPolicy(bool $flag): self
    {
        $obj = clone $this;
        $obj->_explicitPolicy = $flag;
        return $obj;
    }

    /**
     * Get self with initial-any-policy-inhibit set.
     */
    public function withAnyPolicyInhibit(bool $flag): self
    {
        $obj = clone $this;
        $obj->_anyPolicyInhibit = $flag;
        return $obj;
    }

    /**
     * Get self with user-initial-policy-set set to policy OIDs.
     *
     * @param string ...$policies List of policy OIDs
     */
    public function withPolicySet(string ...$policies): self
    {
        $obj = clone $this;
        $obj->_policySet = $policies;
        return $obj;
    }

    /**
     * Get maximum certification path length.
     */
    public function maxLength(): int
    {
        return $this->_maxLength;
    }

    /**
     * Get reference date and time.
     */
    public function dateTime(): DateTimeImmutable
    {
        return $this->_dateTime;
    }

    /**
     * Get user-initial-policy-set.
     *
     * @return string[] Array of OID's
     */
    public function policySet(): array
    {
        return $this->_policySet;
    }

    /**
     * Check whether trust anchor certificate is set.
     */
    public function hasTrustAnchor(): bool
    {
        return isset($this->_trustAnchor);
    }

    /**
     * Get trust anchor certificate.
     */
    public function trustAnchor(): Certificate
    {
        if (! $this->hasTrustAnchor()) {
            throw new LogicException('No trust anchor.');
        }
        return $this->_trustAnchor;
    }

    public function policyMappingInhibit(): bool
    {
        return $this->_policyMappingInhibit;
    }

    public function explicitPolicy(): bool
    {
        return $this->_explicitPolicy;
    }

    public function anyPolicyInhibit(): bool
    {
        return $this->_anyPolicyInhibit;
    }
}
