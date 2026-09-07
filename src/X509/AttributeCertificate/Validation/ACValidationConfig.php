<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate\Validation;

use DateTimeImmutable;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Provides configuration context for the attribute certificate validation.
 */
final class ACValidationConfig
{
    /**
     * Evaluation reference time.
     */
    private DateTimeImmutable $evalTime;

    /**
     * Permitted targets.
     *
     * @var Target[]
     */
    private array $targets;

    /**
     * Configuration applied when validating the holder and issuer certification paths.
     */
    private PathValidationConfig $pathValidationConfig;

    /**
     * @param CertificationPath $holderPath Certification path of the AC holder
     * @param CertificationPath $issuerPath Certification path of the AC issuer
     */
    private function __construct(
        private readonly CertificationPath $holderPath,
        private readonly CertificationPath $issuerPath
    ) {
        $this->evalTime = new DateTimeImmutable();
        $this->targets = [];
        $this->pathValidationConfig = PathValidationConfig::defaultConfig();
    }

    public static function create(CertificationPath $holderPath, CertificationPath $issuerPath): self
    {
        return new self($holderPath, $issuerPath);
    }

    /**
     * Get certification path of the AC's holder.
     */
    public function holderPath(): CertificationPath
    {
        return $this->holderPath;
    }

    /**
     * Get certification path of the AC's issuer.
     */
    public function issuerPath(): CertificationPath
    {
        return $this->issuerPath;
    }

    /**
     * Get self with the configuration used to validate the holder and issuer certification paths.
     *
     * Without this, those two paths are validated on the default configuration and the caller cannot express any
     * policy for them, including which signature algorithms are acceptable. The maximum path length and the
     * evaluation time are still derived from this object.
     */
    public function withPathValidationConfig(PathValidationConfig $config): self
    {
        $obj = clone $this;
        $obj->pathValidationConfig = $config;
        return $obj;
    }

    /**
     * Get the configuration used to validate the holder and issuer certification paths.
     */
    public function pathValidationConfig(): PathValidationConfig
    {
        return $this->pathValidationConfig;
    }

    /**
     * Get self with given evaluation reference time.
     */
    public function withEvaluationTime(DateTimeImmutable $dt): self
    {
        $obj = clone $this;
        $obj->evalTime = $dt;
        return $obj;
    }

    /**
     * Get the evaluation reference time.
     */
    public function evaluationTime(): DateTimeImmutable
    {
        return $this->evalTime;
    }

    /**
     * Get self with permitted targets.
     */
    public function withTargets(Target ...$targets): self
    {
        $obj = clone $this;
        $obj->targets = $targets;
        return $obj;
    }

    /**
     * Get array of permitted targets.
     *
     * @return Target[]
     */
    public function targets(): array
    {
        return $this->targets;
    }
}
