<?php

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\X501\ASN1\Attribute;
use Sop\X509\AttributeCertificate\AttCertValidityPeriod;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\AuthenticationInfoAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\AttributeCertificateInfo;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\AttributeCertificate\V2Form;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Sop\X509\Certificate\Extension\NoRevocationAvailableExtension;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\Certificate\Extension\Target\Targets;
use Sop\X509\Certificate\Extension\TargetInformationExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

require_once dirname(dirname(dirname(__DIR__))) . '/vendor/autoload.php';

// load issuer certificate
$issuer_cert = Certificate::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/certs/acme-rsa.pem'));
// load issuer private and public keys
$issuer_private_key = PrivateKey::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/certs/keys/acme-rsa.pem'))->privateKeyInfo();
$issuer_public_key = $issuer_private_key->publicKeyInfo();
// load AC holder certificate
$holder_cert = Certificate::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/certs/acme-ecdsa.pem'));

$holder = new Holder(IssuerSerial::fromPKC($holder_cert),
    new GeneralNames(
        new DirectoryName($holder_cert->tbsCertificate()->subject())));
$issuer = new V2Form(
    new GeneralNames(
        new DirectoryName($issuer_cert->tbsCertificate()->subject())));
$validity = AttCertValidityPeriod::fromStrings('2016-01-01 12:00:00',
    '2016-03-01 12:00:00', 'UTC');
$authinfo_attr = new AuthenticationInfoAttributeValue(
    new UniformResourceIdentifier('urn:service'),
    DirectoryName::fromDNString('cn=username'), 'password');
$authid_attr = new AccessIdentityAttributeValue(
    new UniformResourceIdentifier('urn:service'),
    DirectoryName::fromDNString('cn=username'));
$charge_attr = new ChargingIdentityAttributeValue(
    IetfAttrValue::fromString('ACME Ltd.'));
$charge_attr = $charge_attr->withPolicyAuthority(
    new GeneralNames(DirectoryName::fromDNString('cn=ACME Ltd.')));
$group_attr = new GroupAttributeValue(IetfAttrValue::fromString('group1'),
    IetfAttrValue::fromString('group2'));
$role_attr = Attribute::fromAttributeValues(
    new RoleAttributeValue(new UniformResourceIdentifier('urn:role1')),
    new RoleAttributeValue(new UniformResourceIdentifier('urn:role2')));
$attribs = Attributes::fromAttributeValues($authinfo_attr, $authid_attr,
    $charge_attr, $group_attr)->withAdditional($role_attr);
$aki_ext = new AuthorityKeyIdentifierExtension(false,
    $issuer_public_key->keyIdentifier());
$ti_ext = new TargetInformationExtension(true,
    new Targets(new TargetName(new UniformResourceIdentifier('urn:test')),
        new TargetName(new DNSName('*.example.com'))),
    new Targets(new TargetName(new UniformResourceIdentifier('urn:another'))));
$nra_ext = new NoRevocationAvailableExtension(false);
$extensions = new Extensions($aki_ext, $nra_ext, $ti_ext);
$aci = new AttributeCertificateInfo($holder, $issuer, $validity, $attribs);
$aci = $aci->withSerialNumber(0xbadcafe);
$aci = $aci->withExtensions($extensions);
$ac = $aci->sign(new SHA256WithRSAEncryptionAlgorithmIdentifier(),
    $issuer_private_key);
echo $ac;
