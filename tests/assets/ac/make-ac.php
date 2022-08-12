<?php

declare(strict_types=1);

use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\AuthenticationInfoAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\IetfAttrValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\AttributeCertificate\V2Form;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\NoRevocationAvailableExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetName;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Targets;
use SpomkyLabs\Pki\X509\Certificate\Extension\TargetInformationExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

require_once dirname(__DIR__, 3) . '/vendor/autoload.php';

// load issuer certificate
$issuer_cert = Certificate::fromPEM(PEM::fromFile(dirname(__DIR__) . '/certs/acme-rsa.pem'));
// load issuer private and public keys
$issuer_private_key = PrivateKey::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/certs/keys/acme-rsa.pem')
)->privateKeyInfo();
$issuer_public_key = $issuer_private_key->publicKeyInfo();
// load AC holder certificate
$holder_cert = Certificate::fromPEM(PEM::fromFile(dirname(__DIR__) . '/certs/acme-ecdsa.pem'));

$holder = new Holder(
    IssuerSerial::fromPKC($holder_cert),
    new GeneralNames(new DirectoryName($holder_cert->tbsCertificate()->subject()))
);
$issuer = new V2Form(new GeneralNames(new DirectoryName($issuer_cert->tbsCertificate()->subject())));
$validity = AttCertValidityPeriod::fromStrings('2016-01-01 12:00:00', '2016-03-01 12:00:00', 'UTC');
$authinfo_attr = AuthenticationInfoAttributeValue::create(
    new UniformResourceIdentifier('urn:service'),
    DirectoryName::fromDNString('cn=username'),
    'password'
);
$authid_attr = new AccessIdentityAttributeValue(
    new UniformResourceIdentifier('urn:service'),
    DirectoryName::fromDNString('cn=username')
);
$charge_attr = ChargingIdentityAttributeValue::create(IetfAttrValue::fromString('ACME Ltd.'));
$charge_attr = $charge_attr->withPolicyAuthority(new GeneralNames(DirectoryName::fromDNString('cn=ACME Ltd.')));
$group_attr = GroupAttributeValue::create(IetfAttrValue::fromString('group1'), IetfAttrValue::fromString('group2'));
$role_attr = Attribute::fromAttributeValues(
    new RoleAttributeValue(new UniformResourceIdentifier('urn:role1')),
    new RoleAttributeValue(new UniformResourceIdentifier('urn:role2'))
);
$attribs = Attributes::fromAttributeValues(
    $authinfo_attr,
    $authid_attr,
    $charge_attr,
    $group_attr
)->withAdditional($role_attr);
$aki_ext = new AuthorityKeyIdentifierExtension(false, $issuer_public_key->keyIdentifier());
$ti_ext = new TargetInformationExtension(
    true,
    new Targets(
        new TargetName(new UniformResourceIdentifier('urn:test')),
        new TargetName(new DNSName('*.example.com'))
    ),
    new Targets(new TargetName(new UniformResourceIdentifier('urn:another')))
);
$nra_ext = new NoRevocationAvailableExtension(false);
$extensions = new Extensions($aki_ext, $nra_ext, $ti_ext);
$aci = new AttributeCertificateInfo($holder, $issuer, $validity, $attribs);
$aci = $aci->withSerialNumber(0xbadcafe);
$aci = $aci->withExtensions($extensions);
$ac = $aci->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $issuer_private_key);
echo $ac;
