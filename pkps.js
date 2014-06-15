/* JavaScript Public-Key-Pins calculator - JavaScript library for easy 
 * calculation of public key hashes for use in Public Key Pinning Extension for HTTP.
 * Version 1.0
 * Copyright (C) 2014 Davis Mosenkovs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 */

/** Namespace definition */
var pkps = pkps || {};

/**
 * Generates public key hashes for specified set of certificates and/or CSRs.
 * This is the object of this library that will most likely be used externally.
 * Currently only RSA keys are supported.
 * Mandatory selftests are invoked automatically each time object of this type is created.
 *
 * @param certificatesAndCsrs newline or space separated certificates and/or certificate signing requests in PEM format.
 * @return publicKeyPinsSet object with set of the hashes.
 *   getCount(), formatReport(), hasWarnings(), formatWarnings(), formatPKPHeaderComplete()
 *   and formatPKPHeaderValue() methods of this object should be used.
 * @throws Error object with textual description of failure as message.
 */
pkps.publicKeyPinsSet = function(certificatesAndCsrs) {
    this.pins = new Array();
    this.inputs = new Array();
    this.warnings = new Array();

    var pems = null;
    var i, j;
    var pi_nondns = false;
    var pi_diffcn = false;
    var pi_samekey = false;
    var validHostnameRegex = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/; // credits to http://stackoverflow.com/questions/106179

    // invoke selftests
    pkps.doSelfTests();

    // split input
    pems = certificatesAndCsrs.split("-----BEGIN ");
    if(pems.length<2 || pems[0].trim()!=="")
        throw new Error("Unable to split input into PEM certificates/CSRs.");

    // generate Public-Key-Pins
    for(i=1; i<pems.length; i++) {
        this.pins.push(new pkps.publicKeyPin("-----BEGIN "+pems[i].trim()));
        this.inputs.push("-----BEGIN "+pems[i].trim());
    }

    // verify result count
    if(this.pins.length!==this.inputs.length || this.pins.length!==pems.length-1)
        throw new Error("Internal error occurred.");

    // detect possible issues
    for(i=0; i<this.pins.length; i++) {
        // different common names
        if(this.pins[i].getCN()!==this.pins[0].getCN())
            pi_diffcn = true;
        // common names that are not hostnaames
        if(this.pins[i].getCN().match(validHostnameRegex)==null)
            pi_nondns = true;
        // duplicate public keys
        for(j=0; j<i; j++) {
            if(this.pins[i].getPublicKeyPem()==this.pins[j].getPublicKeyPem())
                pi_samekey = true;
        }
    }
    if(pi_diffcn)
        this.warnings.push("Different Common Names (CNs) detected. Don't continue unless you really know what you are doing! Don't paste full certificate chain (CA bundle) here!");
    if(pi_nondns)
        this.warnings.push("Not all Common Names (CNs) are host names (DNS records). It is recommended to pin only keys you control (or really trust). Note that third-party CAs may change their keys and do less validations when signing new certificates for known hostnames (CNs).");
    if(pi_samekey)
        this.warnings.push("Multiple certificates/CSRs contain the same public key. This should be caused by user error (e.g. pasting single PEM two times).");
    if(this.pins.length<2)
        this.warnings.push("At least two pins (one of them must be backup pin - pin of securely held offline backup key) are required by the standard.");
    if(this.pins.length<3)
        this.warnings.push("Three or more pins (two or more backup key pins - pins of securely held offline backup keys) are recommended.");
}

/**
 * Returns number of certificates/CSRs processed in publicKeyPinsSet.
 *
 * @return integer with number of objects processed, that is number of pins, that is number entries in report.
 */
pkps.publicKeyPinsSet.prototype.getCount = function() {
    return this.pins.length;
}

/**
 * Creates/formats report into displayable string.
 *
 * @param formatString string with template.
 *   This string is repeated for each certificate/CSR
 *   replacing all instances of "{Input}" (without quotes) with object from which public key was extracted,
 *   replacing all instances of "{Type}" (without quotes) with type of object from which public key was extracted ("Certificate" or "CSR"),
 *   replacing all instances of "{PublicKey}" (without quotes) with public key in PEM format,
 *   replacing all instances of "{CN}" (without quotes) with Common Name,
 *   replacing all instances of "{SHA256Hex}" (without quotes) with SHA256 hash in hex format of public key,
 *   replacing all instances of "{SHA256}" (without quotes) with SHA256 hash in Base64 format of public key.
 * @return string with formatted report.
 */
pkps.publicKeyPinsSet.prototype.formatReport = function(formatString) {
    var i;
    var ret = "";

    for(i=0; i<this.pins.length; i++) {
        ret += formatString
                 .replace(/\{Input\}/i, this.inputs[i])
                 .replace(/\{Type\}/i, this.pins[i].getType())
                 .replace(/\{PublicKey\}/i, this.pins[i].getPublicKeyPem())
                 .replace(/\{CN\}/i, this.pins[i].getCN())
                 .replace(/\{SHA256Hex\}/i, this.pins[i].getPublicKeyHash("sha256", true))
                 .replace(/\{SHA256\}/i, this.pins[i].getPublicKeyHash("sha256"));
    }
    return ret;
}

/**
 * Checks whether publicKeyPinsSet has any warnings.
 *
 * @return boolean whether publicKeyPinsSet has warnings.
 */
pkps.publicKeyPinsSet.prototype.hasWarnings = function() {
    return this.warnings.length>0;
}

/**
 * Formats and concatenates warnings into displayable string.
 *
 * @param formatString string with template.
 *   This string is repeated for each warning
 *   replacing all instances of "{Warning}" (without quotes) with corresponding warning.
 * @return string with formatted and concatenated warnings.
 */
pkps.publicKeyPinsSet.prototype.formatWarnings = function(formatString) {
    var i;
    var ret = "";

    for(i=0; i<this.warnings.length; i++) {
        ret += formatString.replace(/\{Warning\}/i, this.warnings[i]);
    }
    return ret;
}

/**
 * Generates/formats value of Public-Key-Pins HTTP header.
 *
 * @param maxAge integer value of max-age directive.
 * @param includeSubDomains boolean whether to add includeSubDomains directive.
 * @return string with value of Public-Key-Pins HTTP header.
 * @throws Error object with textual description of failure as message, if called incorrectly.
 */
pkps.publicKeyPinsSet.prototype.formatPKPHeaderValue = function(maxAge, includeSubDomains) {
    // input validation
    if(typeof(maxAge)!=="number" || maxAge<1 || maxAge.toString().match(/^[0-9]+$/)==null)
        throw new Error("getPKPHeader() called with incorrect maxAge");
    if(typeof(includeSubDomains)!=="boolean")
        throw new Error("getPKPHeader() called with incorrect includeSubDomains");

    var i;
    var ret = "";

    for(i=0; i<this.pins.length; i++) {
        ret += "pin-sha256=\""+this.pins[i].getPublicKeyHash("sha256")+"\"; ";
    }
    ret += "max-age="+maxAge;
    if(includeSubDomains)
        ret += "; includeSubDomains";
    return ret;
}

/**
 * Generates/formats complete Public-Key-Pins HTTP header.
 *
 * @param maxAge integer value of max-age directive.
 * @param includeSubDomains boolean whether to add includeSubDomains directive.
 * @return string with complete Public-Key-Pins HTTP header.
 * @throws Error object with textual description of failure as message, if called incorrectly.
 */
pkps.publicKeyPinsSet.prototype.formatPKPHeaderComplete = function(maxAge, includeSubDomains) {
    return "Public-Key-Pins: "+this.formatPKPHeaderValue(maxAge, includeSubDomains);
}

/**
 * Generates/formats value of HSTS HTTP header.
 *
 * @param maxAge integer value of max-age directive.
 * @param includeSubDomains boolean whether to add includeSubDomains directive.
 * @return string with value of HSTS HTTP header.
 * @throws Error object with textual description of failure as message, if called incorrectly.
 */
pkps.formatHSTSHeaderValue = function(maxAge, includeSubDomains) {
    // input validation
    if(typeof(maxAge)!=="number" || maxAge<1 || maxAge.toString().match(/^[0-9]+$/)==null)
        throw new Error("getHSTSHeader() called with incorrect maxAge");
    if(typeof(includeSubDomains)!=="boolean")
        throw new Error("getHSTSHeader() called with incorrect includeSubDomains");

    var ret = "max-age="+maxAge;
    if(includeSubDomains)
        ret += "; includeSubDomains";
    return ret;
}

/**
 * Generates/formats complete HSTS HTTP header.
 *
 * @param maxAge integer value of max-age directive.
 * @param includeSubDomains boolean whether to add includeSubDomains directive.
 * @return string with complete HSTS HTTP header.
 * @throws Error object with textual description of failure as message, if called incorrectly.
 */
pkps.formatHSTSHeaderComplete = function(maxAge, includeSubDomains) {
    return "Strict-Transport-Security: "+pkps.formatHSTSHeaderValue(maxAge, includeSubDomains);
}

/**
 * Generates public key hashes for specified certificate or CSR.
 * Currently only RSA keys are supported.
 * Before calling this method, pkps.doSelfTests() must have been called.
 *
 * @param certificateOrCsr certificate or certificate signing request in PEM format.
 * @return publicKeyPin object with the hashes (and other data).
 *   getPublicKeyHash() and getPublicKeyPem() methods of this object should be used.
 * @throws Error object with textual description of failure as message.
 */
pkps.publicKeyPin = function(certificateOrCsr) {
    // input validation
    if(typeof(certificateOrCsr)!=="string" || certificateOrCsr.length<220)
        throw new Error("Unable to decode input.");

    // allow only after selftests have been passed (excl. selftest values)
    if(certificateOrCsr!==pkps.self_tests_crtPEM && certificateOrCsr!==pkps.self_tests_csrPEM && (typeof(pkps.self_tests_for_PublicKeyPins_JS_calculator)!=="string" || pkps.self_tests_for_PublicKeyPins_JS_calculator!=="selftests_passed_OK"))
        throw new Error("Self tests must be passed before doing any real calculations.");

    this.pk = null;
    this.pkpem = null;
    this.keysize = null;
    this.type = null;
    this.cn = null;
    this.hashes = new Array();

    var cert = null;

    try {
        // first try decoding as certificate, fail over to csr
        try {
            cert = forge.pki.certificateFromPem(certificateOrCsr);
            this.type = "Certificate";
        } 
        catch(e) {
            cert = forge.pki.certificationRequestFromPem(certificateOrCsr);
            this.type = "CSR";
        }
    }
    catch(e) {
        throw new Error("Unable to decode certificate/CSR.");
    }

    try {
        // extract public key
        this.pkpem = forge.pki.publicKeyToPem(cert.publicKey);
        if(typeof(this.pkpem)!=="string" || this.pkpem.length<220) // check PEM length
            throw 1;
        var pkdpem = forge.pem.decode(this.pkpem);
        if(pkdpem.length!==1) // ensure that private key is a single PEM message
            throw 2;
        this.pk = pkdpem[0].body;
        this.keysize = pkdpem[0].body.length;
        if(this.keysize<128) // check key length
            throw 3;
    }
    catch(e) {
        throw new Error("Unable extract public key.");
    }

    try {
        // extract Common Name
        this.cn = cert.subject.getField("CN").value;
        if(typeof(this.cn)!=="string" || this.cn.length<1)
            throw 1;
    }
    catch(e) {
        throw new Error("Unable extract Common Name.");
    }

    try {
        // generate hashes
        this.addHash("sha1", forge.md.sha1, 20);
        this.addHash("sha256", forge.md.sha256, 32);
        this.addHash("sha384", forge.md.sha384, 48);
        this.addHash("sha512", forge.md.sha512, 64);
    }
    catch(e) {
        throw new Error("Error generating hashes.");
    }
}

// for internal use only - generates and stores a hash
pkps.publicKeyPin.prototype.addHash = function(hashType, forgeMd, dSize) {
    var md = forgeMd.create();
    if(typeof(this.pk)!=="string" || this.keysize!==this.pk.length) // check key length
        throw 1;
    md.update(this.pk);
    this.hashes[hashType] = { base64: forge.util.encode64(md.digest().getBytes()), 
                              hex: md.digest().toHex() };
    // check that digest is encoded properly
    var hcheck1 = forge.util.hexToBytes(this.hashes[hashType].hex);
    var hcheck2 = forge.util.decode64(this.hashes[hashType].base64);
    if(hcheck1!==hcheck2 || hcheck1.length!==dSize || hcheck2.length!==dSize)
        throw 2;
}

// for internal use only - self-test certificate and CSR
pkps.self_tests_crtPEM = "-----BEGIN CERTIFICATE-----\r\nMIIDajCCAlICCQCOMMZ0DNdT0zANBgkqhkiG9w0BAQUFADB3MQswCQYDVQQGEwJY\r\nWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBh\r\nbnkgTHRkMTMwMQYDVQQDDCpodHRwczovL2dpdGh1Yi5jb20vRGF2aXNOVC9QdWJs\r\naWMtS2V5LVBpbnMwHhcNMTQwNTMwMjEyMDU3WhcNMTUwNTMwMjEyMDU3WjB3MQsw\r\nCQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\r\ndWx0IENvbXBhbnkgTHRkMTMwMQYDVQQDDCpodHRwczovL2dpdGh1Yi5jb20vRGF2\r\naXNOVC9QdWJsaWMtS2V5LVBpbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\r\nAoIBAQC3LSDIUB6UE4je4wBVOH1fYTdxOrV851L1vCLwzrmzwDd0nL4SYJ6BjJBt\r\n6V6XeAlAfsD19qBf4AIso9vAPRe4GX4EMirefOp3o8d94YIlEW2I1ueXZhwrRYWR\r\ncD1EIDmt11cHVHorfEzhc24GBjKZXP2lyOJzCN9iSQnVSs46/NpAyB0GhW6bUE6E\r\nBSMnQP2SvV89L7yeqtcsOBHp2Jb9xH63c0ujb9XMxIBqoCdSDz+K+rtE/VfVOC53\r\nwf3p3RZ5I1reSfMCzKoiEkNf/0GFmddhW/yIp2UbPXoy9AXmsLLjJlrfzmbeER2e\r\nr6v/6cG3prwRhCBDORaHkM6MQtwTAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAFMd\r\nuIzwwmQAtkB1wHpa9Xk/9Z6Hy6zj2QIsrwyx6gaxiTLRHfWok8UhLg0/LYfqCRnj\r\nrNqiGDlljBFIdznge7aVrc5rBNbk4wmVMsnHATxOsR2VE9GwVO7ahlVt+Oz5eTUl\r\n19Z0HYlkS2iFF8QrKiShqNNHKTKzNGBSj6aIhAnkflF1nIzoG/pvsDfdZmbkNNEW\r\n9jV6c3MrZt5tWSLULcodp6XguSLqyNceEqhmSUCDcMxdPPlhIWRU2S/HyGBWY5+N\r\nYUzjvAo5H5I7lZt/wSB5f4KAcw+hlyk6S1mv7U0JkA6fVV2ZeAPlDjYduK4aAgLk\r\nCqOCYoTPWdas6HWkrFo=\r\n-----END CERTIFICATE-----\r\n";
pkps.self_tests_csrPEM = "-----BEGIN CERTIFICATE REQUEST-----\r\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0\r\neTEcMBoGA1UECgwTRGVmYXVsdCBDb21wYW55IEx0ZDEzMDEGA1UEAwwqaHR0cHM6\r\nLy9naXRodWIuY29tL0RhdmlzTlQvUHVibGljLUtleS1QaW5zMIIBIjANBgkqhkiG\r\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty0gyFAelBOI3uMAVTh9X2E3cTq1fOdS9bwi\r\n8M65s8A3dJy+EmCegYyQbelel3gJQH7A9fagX+ACLKPbwD0XuBl+BDIq3nzqd6PH\r\nfeGCJRFtiNbnl2YcK0WFkXA9RCA5rddXB1R6K3xM4XNuBgYymVz9pcjicwjfYkkJ\r\n1UrOOvzaQMgdBoVum1BOhAUjJ0D9kr1fPS+8nqrXLDgR6diW/cR+t3NLo2/VzMSA\r\naqAnUg8/ivq7RP1X1Tgud8H96d0WeSNa3knzAsyqIhJDX/9BhZnXYVv8iKdlGz16\r\nMvQF5rCy4yZa385m3hEdnq+r/+nBt6a8EYQgQzkWh5DOjELcEwIDAQABoAAwDQYJ\r\nKoZIhvcNAQEFBQADggEBAH9PQ9eo+1ASvE27LHqJGJeAlY+aAI8VYMytod9yWBVl\r\ngwkoL97BxI28ZcWdQj3jWU1nYXGRUt6W4R/Z6UVB1YLKZ+4dYSaawDI3BdEwfqPt\r\nLeLxshgBf9f3NOzQa5OpyOlpXZzP9H9Fo9EYj6IpYLKPZaQX5t8/9/c3fpVbcYD/\r\neSl7GWUhOwK5KqpqYySuyL4I8y4BbzSvoouGUpGU+IghRShqI+rqnOPUuhNy14g2\r\nd5tMIkJJOg0Y124kpMcbDtsFKfKaRKm1NP+TvUN/WINK6DrMZc5wDJsrf2TiErAp\r\nC1icgpEM3snczBZPBG0cmJPOc72tHJM0/do31M864WM=\r\n-----END CERTIFICATE REQUEST-----\r\n";

/**
 * Returns public key in PEM format.
 *
 * @return string with properly formatted text with public key in PEM format.
 */
pkps.publicKeyPin.prototype.getPublicKeyPem = function() {
    return this.pkpem;
}

/**
 * Returns type of object from which public key was extracted.
 *
 * @return string of whether "Certificate" or "CSR".
 */
pkps.publicKeyPin.prototype.getType = function() {
    return this.type;
}

/**
 * Returns Common Name (CN attribute) of object from which public key was extracted.
 *
 * @return string with Common Name.
 */
pkps.publicKeyPin.prototype.getCN = function() {
    return this.cn;
}

/**
 * Returns public key hash.
 *
 * @param hashType the hash type to return.
 *   Allowed values are "sha1", "sha256", "sha384" and "sha512".
 *   NB! Not all of these hash types may be used in Public-Key-Pins header.
 * @param hex specifies to return hash in hex format.
 *   Boolean true must be specified or this parameter must be omitted.
 * @return string with public key hash either in Base64 or hex format.
 * @throws Error object with textual description of failure as message, if called incorrectly.
 */
pkps.publicKeyPin.prototype.getPublicKeyHash = function(hashType, hex) {
    if(typeof(this.hashes[hashType])!=="object")
        throw new Error("getPublicKeyHash() called with incorrect hashType");
    if(typeof(hex)==="undefined")
        return this.hashes[hashType].base64;
    if(hex===true)
        return this.hashes[hashType].hex;
    throw new Error("getPublicKeyHash() called with incorrect parameter hex value");
}

/**
 * Performs mandatory selftests to ensure that JavaScript Public-Key-Pins calculator 
 * works properly on given JavaScript engine.
 * All computed hashes of dummy certificate and dummy CSR are tested.
 * Before creating any pkps.publicKeyPin() objects, this method must have been called.
 *
 * @throws Error object with textual description of failure as message.
 */
pkps.doSelfTests = function() {
    try {
        var pkpsTestCrt = new pkps.publicKeyPin(pkps.self_tests_crtPEM);
        var pkpsTestCsr = new pkps.publicKeyPin(pkps.self_tests_csrPEM);
    }
    catch(e) {
        throw new Error("An error occurred while computing selftest hashes.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.");
    }
    if(Object.keys(pkpsTestCrt.hashes).length!==4)
        throw new Error("Not all hashes are tested.");
    try {
        if(
          // verify certificate and CSR data
             pkpsTestCrt.getPublicKeyPem()!==pkpsTestCsr.getPublicKeyPem()
          || pkpsTestCrt.getPublicKeyPem().length!==460
          || pkpsTestCrt.getType()!=="Certificate"
          || pkpsTestCsr.getType()!=="CSR"
          || pkpsTestCrt.getCN()!==pkpsTestCsr.getCN()
          || pkpsTestCrt.getCN().length!==42
        )
            throw 2;

        if(
          // verify all certificate hashes
             pkpsTestCrt.getPublicKeyHash("sha1", true)==="0e5141dbaa777f806f8a203c2a56a873fcf0ad95"
          && pkpsTestCrt.getPublicKeyHash("sha1")==="DlFB26p3f4BviiA8Klaoc/zwrZU="
          && pkpsTestCrt.getPublicKeyHash("sha256", true)==="d4c45a8df4da85f126efafb820d2bd8ce0b0304255da01fce33029e2917f24eb"
          && pkpsTestCrt.getPublicKeyHash("sha256")==="1MRajfTahfEm76+4INK9jOCwMEJV2gH84zAp4pF/JOs="
          && pkpsTestCrt.getPublicKeyHash("sha384", true)==="a8aae4db1a1c3b5efeb37d1e26425ec81255b7bea6c968f65aceff9f336f4647ec13339aac3d2b7b0570de7524a3ad2a"
          && pkpsTestCrt.getPublicKeyHash("sha384")==="qKrk2xocO17+s30eJkJeyBJVt76myWj2Ws7/nzNvRkfsEzOarD0rewVw3nUko60q"
          && pkpsTestCrt.getPublicKeyHash("sha512", true)==="73fe33324f10f6150a70a7ae67a17f4b4573fc98849e2f8e92f2ae58e075560e62b531a0901f23ab63c841b55734f495b8c8fb7b0a0bb582e485d4f0283b81d7"
          && pkpsTestCrt.getPublicKeyHash("sha512")==="c/4zMk8Q9hUKcKeuZ6F/S0Vz/JiEni+OkvKuWOB1Vg5itTGgkB8jq2PIQbVXNPSVuMj7ewoLtYLkhdTwKDuB1w=="
          // verify all CSR hashes
          && pkpsTestCsr.getPublicKeyHash("sha1", true)==="0e5141dbaa777f806f8a203c2a56a873fcf0ad95"
          && pkpsTestCsr.getPublicKeyHash("sha1")==="DlFB26p3f4BviiA8Klaoc/zwrZU="
          && pkpsTestCsr.getPublicKeyHash("sha256", true)==="d4c45a8df4da85f126efafb820d2bd8ce0b0304255da01fce33029e2917f24eb"
          && pkpsTestCsr.getPublicKeyHash("sha256")==="1MRajfTahfEm76+4INK9jOCwMEJV2gH84zAp4pF/JOs="
          && pkpsTestCsr.getPublicKeyHash("sha384", true)==="a8aae4db1a1c3b5efeb37d1e26425ec81255b7bea6c968f65aceff9f336f4647ec13339aac3d2b7b0570de7524a3ad2a"
          && pkpsTestCsr.getPublicKeyHash("sha384")==="qKrk2xocO17+s30eJkJeyBJVt76myWj2Ws7/nzNvRkfsEzOarD0rewVw3nUko60q"
          && pkpsTestCsr.getPublicKeyHash("sha512", true)==="73fe33324f10f6150a70a7ae67a17f4b4573fc98849e2f8e92f2ae58e075560e62b531a0901f23ab63c841b55734f495b8c8fb7b0a0bb582e485d4f0283b81d7"
          && pkpsTestCsr.getPublicKeyHash("sha512")==="c/4zMk8Q9hUKcKeuZ6F/S0Vz/JiEni+OkvKuWOB1Vg5itTGgkB8jq2PIQbVXNPSVuMj7ewoLtYLkhdTwKDuB1w=="
        ) 
            pkps.self_tests_for_PublicKeyPins_JS_calculator="selftests_passed_OK";
        else
            throw 1;
    }
    catch(e) {
        if(typeof(e)==="number" && e===1)
            throw new Error("Selftest hash(es) were computed incorrectly.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.");
        else if(typeof(e)==="number" && e===2)
            throw new Error("Selftest certificate or CSR data were extracted incorrectly.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.");
        else
            throw new Error("An error occurred while accessing selftest hashes or certificate/CSR data.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.");
    }
}
