<?php

// generate a random string of the given size
//
// @size: string size
//
// return: 
//   the random string

function generateRand($size) {
	$res = '';
	$chars = 'abcdefghijklmonpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	for($i = 0; $i < $size; $i++) {
		$res .= $chars[rand(0, strlen($chars)-1)];
	}
	return $res;
}

// verify the digest value
// the digest value is the SHA1 of a part of the XML document.
// This digest value is part of the 
//
// @content: string of and XML document the verify
//
// return: 
//   - the digested part of the XML document if the digest is correct
//   - null if the digest is not valid

function calculateDigest($node) {

	// create a document only with the reference part
	$refNodeDoc = new DOMDocument('1.0');
	$refNodeDoc->loadXML($node->C14N());

	$digestValue = base64_encode(sha1($refNodeDoc->C14N(true), TRUE));
	return $digestValue;
}

function generateSignature($privateKey, $digestValue, $refId) {
	$ds = 'http://www.w3.org/2000/09/xmldsig#';

	$signedInfoDom = new DOMDocument('1.0');

	$signedInfo = $signedInfoDom->createElementNS($ds, 'ds:SignedInfo');
	$signedInfoDom->appendChild($signedInfo);

	$canonicalizationMethod = $signedInfoDom->createElementNS($ds, 'CanonicalizationMethod');
	$canonicalizationMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
	$signedInfo->appendChild($canonicalizationMethod);

	$signatureMethod = $signedInfoDom->createElementNS($ds, 'SignatureMethod');
	$signatureMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
	$signedInfo->appendChild($signatureMethod);

	$reference = $signedInfoDom->createElementNS($ds, 'Reference');
	$reference->setAttribute('URI', '#'.$refId);
	$signedInfo->appendChild($reference);

	$transforms = $signedInfoDom->createElementNS($ds, 'Transforms');
	$reference->appendChild($transforms);

	$transform = $signedInfoDom->createElementNS($ds, 'Transform');
	$transform->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
	$transforms->appendChild($transform);

	$transform = $signedInfoDom->createElementNS($ds, 'Transform');
	$transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
	$transforms->appendChild($transform);

	$digestMethod = $signedInfoDom->createElementNS($ds, 'DigestMethod');
	$digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
	$reference->appendChild($digestMethod);

	$digestValueNode = $signedInfoDom->createElementNS($ds, 'DigestValue');
	$digestValueNode->nodeValue = $digestValue;
	$reference->appendChild($digestValueNode);

	// generate the SHA1 RSA signature of the SignedInfo part
	$privkeyid = openssl_pkey_get_private($privateKey);
	openssl_sign($signedInfoDom->C14N(true), $signatureValue, $privkeyid, OPENSSL_ALGO_SHA1);
	openssl_free_key($privkeyid);
	$signatureValue = base64_encode($signatureValue);

	$signatureDom = new DOMDocument('1.0');
	$signature = $signatureDom->createElementNS($ds, 'ds:Signature');
	$signatureDom->appendChild($signature);

	$signature->appendChild($signatureDom->importNode($signedInfo, true));

	$signatureValueNode = $signatureDom->createElementNS($ds, 'ds:SignatureValue');
	$signatureValueNode->nodeValue = $signatureValue;
	$signature->appendChild($signatureValueNode);

	return $signatureDom;
}


function generateSamlResponse($requestId, $AssertionConsumerServiceURL, $attributeName, $attributeValue, $privateKey) {
	$saml = 'urn:oasis:names:tc:SAML:2.0:assertion';

	$now = new DateTime();
	$now->setTimeZone(new DateTimeZone("UTC"));
	$issueInstant = $now->format('Y-m-d\TH:i:s\Z');

	$dateEnd = new DateTime();
	$dateEnd->setTimeZone(new DateTimeZone("UTC"));
	$dateEnd->add(new DateInterval('PT1H0S'));
	$notOnOrAfter = $dateEnd->format('Y-m-d\TH:i:s\Z');

	$responseId = generateRand(10);
	$assertionId = generateRand(10);

	$samlResponseXML = <<<SAMLXML
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="$AssertionConsumerServiceURL" ID="$responseId" InResponseTo="$requestId" IssueInstant="$issueInstant" Version="2.0">
<saml:Issuer>urn:fi:ac-lyon:AA:1.0</saml:Issuer>
<samlp:Status>
  <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
</samlp:Status>
<saml:Assertion ID="$assertionId" IssueInstant="$issueInstant" Version="2.0">
  <saml:Issuer>urn:fi:ac-lyon:AA:1.0</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="urn:fi:ac-lyon:AA:1.0" SPNameQualifier="portail-agents">c2e5a3ea31619e0d16f9aec8d5f3bdda</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData InResponseTo="$requestId" NotOnOrAfter="$notOnOrAfter" Recipient="$AssertionConsumerServiceURL">
      </saml:SubjectConfirmationData>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="$issueInstant" NotOnOrAfter="$notOnOrAfter">
    <saml:AudienceRestriction>
      <saml:Audience>portail-agents</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="$issueInstant" SessionIndex="ba78c66c2c280e99e4b30a6d00fbbb22">
    <saml:SubjectLocality Address="213.245.116.190" DNSName="webdmz1.ac-lyon.fr"></saml:SubjectLocality>
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <saml:Attribute Name="$attributeName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">$attributeValue</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
</samlp:Response>
SAMLXML;

	$dom = new DOMDocument('1.0');
	$dom->loadXML(rtrim($samlResponseXML));

	$xpath = new DOMXpath($dom);
	$xpath->registerNamespace('saml', $saml);

	// get the Assection
	$assertion = $xpath->query('//saml:Assertion')[0];

	$digestValue = calculateDigest($assertion);

	$signature = generateSignature($privateKey, $digestValue, $assertionId);

	$assertion->insertBefore($dom->importNode($signature->documentElement, true), $assertion->firstChild);

	return $dom;
}

$requestId = '';
$AssertionConsumerServiceURL = '';
$idp = 'agents';
$title = 'Agents / Enseignants';

if(isset($_REQUEST['SAMLRequest'])) {
	$samlRequest = gzinflate(base64_decode($_REQUEST['SAMLRequest']));
	$xml = simplexml_load_string($samlRequest);
	$AssertionConsumerServiceURL = $xml->Attributes()->AssertionConsumerServiceURL;
	$requestId = $xml->Attributes()->ID;
}

if(isset($_REQUEST['idp']) && ($_REQUEST['idp'] == 'parents')) {
	$idp = 'parents';
	$title = 'Parents / Elèves';
}

?><!DOCTYPE html>
<html>
<head>
<title>SSO Académie de Lyon</title>
<style>
body {
	color: white;
	background-color: #2b8fcc;
	font-family: "Open Sans", sans-serif;
	font-size: 20px;
}

.btn {
	display: inline-block;
	font-size: 16px;
	text-transform: uppercase;
	padding: 10px 20px;
	border: 1px solid white;
	border-radius: 0;
	background-color: rgba(0, 0, 0, 0.5);
	margin: 5px;
    color: white;
	white-space: nowrap;
	text-decoration: none;
	cursor: pointer;
}

.btn:hover {
	background-color: rgba(91,192,222,0);
}

.logo {
	width: 55%;
	opacity: 0.2;
	position: absolute;
	left: -5%;
	top: -5%;
	-webkit-user-select: none;
}

input[type=text], input[type=password], textarea {
    height: 30px;
    border: 1px solid white;
    background-color: rgba(0,0,0,0.2);
    margin: 5px;
    color: white;
    font-size: 18px;
    padding-left: 10px;
    padding-right: 10px;
}

td {
	padding: 5px;
}
</style>
</head>
<body>
<img draggable="false" class="logo" src="logo-academie-blanc.svg">
<center>
<h1>Portail d'Authentification de l'Académie</h1>
<h2><?php echo $title; ?></h2>
<div style="max-width: 600px; width: 80%; background-color: rgba(255,255,255,0.2); padding: 20px;">
<?php
if(isset($_REQUEST['ctemail']) || isset($_REQUEST['FrEduVecteur'])) {

	if(isset($_REQUEST['ctemail'])) {
		$attributeName = 'ctemail';
		$attributeValue = $_REQUEST['ctemail'];
	}
	else {
		$attributeName = 'FrEduVecteur';
		$attributeValue = $_REQUEST['FrEduVecteur'];
	}

	$privateKey = file_get_contents("aaf-sso.key");

	$samlResponseDom = generateSamlResponse($requestId,
		$AssertionConsumerServiceURL, $attributeName, $attributeValue,
		$privateKey);

	$samlResponse = base64_encode($samlResponseDom->C14N(true));

?>
<form style="text-align: right" method="POST" action="<?php echo $AssertionConsumerServiceURL; ?>">
  <textarea name="SAMLResponse" style="width: calc(100% - 40px); height: 100px;"><?php echo $samlResponse; ?></textarea><br>
  <input type="submit" value="Submit" class="btn"></input>
</form>
<?php
}
else {

	if($idp == 'parents') {
?>
<form method="POST" style="text-align: right">
  <table>
  <tr><td colspan="2">Format: [type]|[nom]|[prenom]|[ENTEleveStructRattachId]|[UAI]</td></tr>
  <tr><td>[type]:</td><td style="text-align: left">1 = parent homme, 2 = parent femme, 3 = élève garçon, 4 = élève fille</td></tr>
  <tr><td>[nom]:</td><td style="text-align: left">Nom de famille</td></tr>
  <tr><td>[prenom]:</td><td style="text-align: left">Prénom</td></tr>
  <tr><td>[ENTEleveStructRattachId]:</td><td style="text-align: left">Id de l'élève. Si parent id de leur enfant</td></tr>
  <tr><td>[UAI]:</td><td style="text-align: left">Code UAI de l'établissement</td></tr>
  </table>
  <br><br>
  FrEduVecteur: <input style="width: 70%" type="text" name="FrEduVecteur" value="3|DUPONT|Paul|1122334|0691234A"></input><br>
  <input type="submit" value="Submit" class="btn"></input>
</form>
<?php
	}
	else {
?>
<form method="POST" style="text-align: right">
  <div style="text-align: left">Adresse email Académique de l'enseignant</div>
  <br><br>
  ctemail: <input style="width: 70%" type="text" name="ctemail" value="Charlotte.Martin@ac-lyon.fr"></input><br>
  <input type="submit" value="Submit" class="btn"></input>
</form>
<?php
	}
}
?>
</div>
</center>
</body>
</html>
