// namespace definition
var pkps = pkps || {};

/**
 * Generates public key hashes for specified certificate or CSR in PEM format.
 * Before calling this method, pkps.doSelfTests() must have been called.
 *
 * @param certificateOrCsr certificate or certificate signing request in PEM format.
 * @return publicKeyPins object with the hashes.
 *   getPublicKeyHash() and getPublicKeyPem() methods should be used on this object.
 * @throws string with textual description of failure.
 */
pkps.publicKeyPins = function(certificateOrCsr) {
    // input validation
    if(typeof(certificateOrCsr)!=="string" || certificateOrCsr.length<220)
        throw "Unable to decode input.";

    // allow only after selftests have been passed (excl. selftest values)
    if(certificateOrCsr!==pkps.self_tests_crtPEM && certificateOrCsr!==pkps.self_tests_csrPEM && (typeof(pkps.self_tests_for_PublicKeyPins_JS_calculator)!=="string" || pkps.self_tests_for_PublicKeyPins_JS_calculator!=="selftests_passed_OK"))
        throw "Self tests must be passed before doing any real calculations.";

    this.pk = null;
    this.pkpem = null;
    this.keysize = null;
    this.type = null;
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
        throw "Unable to decode input.";
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
        throw "Unable extract public key.";
    }

    try {
        // generate hashes
        this.addHash("sha1", forge.md.sha1, 20);
        this.addHash("sha256", forge.md.sha256, 32);
        this.addHash("sha384", forge.md.sha384, 48);
        this.addHash("sha512", forge.md.sha512, 64);
    }
    catch(e) {
        throw "Error generating hashes.";
    }
}

// used internally - generates and stores a hash
pkps.publicKeyPins.prototype.addHash = function(hashType, forgeMd, dSize) {
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

// used internally - self-test certificate and CSR
pkps.self_tests_crtPEM = "-----BEGIN CERTIFICATE-----\r\nMIIDajCCAlICCQCOMMZ0DNdT0zANBgkqhkiG9w0BAQUFADB3MQswCQYDVQQGEwJY\r\nWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBh\r\nbnkgTHRkMTMwMQYDVQQDDCpodHRwczovL2dpdGh1Yi5jb20vRGF2aXNOVC9QdWJs\r\naWMtS2V5LVBpbnMwHhcNMTQwNTMwMjEyMDU3WhcNMTUwNTMwMjEyMDU3WjB3MQsw\r\nCQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\r\ndWx0IENvbXBhbnkgTHRkMTMwMQYDVQQDDCpodHRwczovL2dpdGh1Yi5jb20vRGF2\r\naXNOVC9QdWJsaWMtS2V5LVBpbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\r\nAoIBAQC3LSDIUB6UE4je4wBVOH1fYTdxOrV851L1vCLwzrmzwDd0nL4SYJ6BjJBt\r\n6V6XeAlAfsD19qBf4AIso9vAPRe4GX4EMirefOp3o8d94YIlEW2I1ueXZhwrRYWR\r\ncD1EIDmt11cHVHorfEzhc24GBjKZXP2lyOJzCN9iSQnVSs46/NpAyB0GhW6bUE6E\r\nBSMnQP2SvV89L7yeqtcsOBHp2Jb9xH63c0ujb9XMxIBqoCdSDz+K+rtE/VfVOC53\r\nwf3p3RZ5I1reSfMCzKoiEkNf/0GFmddhW/yIp2UbPXoy9AXmsLLjJlrfzmbeER2e\r\nr6v/6cG3prwRhCBDORaHkM6MQtwTAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAFMd\r\nuIzwwmQAtkB1wHpa9Xk/9Z6Hy6zj2QIsrwyx6gaxiTLRHfWok8UhLg0/LYfqCRnj\r\nrNqiGDlljBFIdznge7aVrc5rBNbk4wmVMsnHATxOsR2VE9GwVO7ahlVt+Oz5eTUl\r\n19Z0HYlkS2iFF8QrKiShqNNHKTKzNGBSj6aIhAnkflF1nIzoG/pvsDfdZmbkNNEW\r\n9jV6c3MrZt5tWSLULcodp6XguSLqyNceEqhmSUCDcMxdPPlhIWRU2S/HyGBWY5+N\r\nYUzjvAo5H5I7lZt/wSB5f4KAcw+hlyk6S1mv7U0JkA6fVV2ZeAPlDjYduK4aAgLk\r\nCqOCYoTPWdas6HWkrFo=\r\n-----END CERTIFICATE-----\r\n";
pkps.self_tests_csrPEM = "-----BEGIN CERTIFICATE REQUEST-----\r\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0\r\neTEcMBoGA1UECgwTRGVmYXVsdCBDb21wYW55IEx0ZDEzMDEGA1UEAwwqaHR0cHM6\r\nLy9naXRodWIuY29tL0RhdmlzTlQvUHVibGljLUtleS1QaW5zMIIBIjANBgkqhkiG\r\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty0gyFAelBOI3uMAVTh9X2E3cTq1fOdS9bwi\r\n8M65s8A3dJy+EmCegYyQbelel3gJQH7A9fagX+ACLKPbwD0XuBl+BDIq3nzqd6PH\r\nfeGCJRFtiNbnl2YcK0WFkXA9RCA5rddXB1R6K3xM4XNuBgYymVz9pcjicwjfYkkJ\r\n1UrOOvzaQMgdBoVum1BOhAUjJ0D9kr1fPS+8nqrXLDgR6diW/cR+t3NLo2/VzMSA\r\naqAnUg8/ivq7RP1X1Tgud8H96d0WeSNa3knzAsyqIhJDX/9BhZnXYVv8iKdlGz16\r\nMvQF5rCy4yZa385m3hEdnq+r/+nBt6a8EYQgQzkWh5DOjELcEwIDAQABoAAwDQYJ\r\nKoZIhvcNAQEFBQADggEBAH9PQ9eo+1ASvE27LHqJGJeAlY+aAI8VYMytod9yWBVl\r\ngwkoL97BxI28ZcWdQj3jWU1nYXGRUt6W4R/Z6UVB1YLKZ+4dYSaawDI3BdEwfqPt\r\nLeLxshgBf9f3NOzQa5OpyOlpXZzP9H9Fo9EYj6IpYLKPZaQX5t8/9/c3fpVbcYD/\r\neSl7GWUhOwK5KqpqYySuyL4I8y4BbzSvoouGUpGU+IghRShqI+rqnOPUuhNy14g2\r\nd5tMIkJJOg0Y124kpMcbDtsFKfKaRKm1NP+TvUN/WINK6DrMZc5wDJsrf2TiErAp\r\nC1icgpEM3snczBZPBG0cmJPOc72tHJM0/do31M864WM=\r\n-----END CERTIFICATE REQUEST-----\r\n";

/**
 * Returns public key in PEM format.
 *
 * @return string with properly formatted text with public key in PEM format.
 */
pkps.publicKeyPins.prototype.getPublicKeyPem = function() {
    return this.pkpem;
}

/**
 * Returns public key hash.
 *
 * @param hashType the hash type to return.
 *   Allowed values are "sha1", "sha256", "sha384" and "sha512".
 * @param hex specifies to return hash in hex format.
 *   Boolean true must be specified or this parameter must be omitted.
 * @return string with public key hash either in Base64 or hex format.
 * @throws string with error description if called incurrectly.
 */
pkps.publicKeyPins.prototype.getPublicKeyHash = function(hashType, hex) {
    if(typeof(this.hashes[hashType])!=="object")
        throw "getPublicKeyHash() called with incorrect hashType";
    if(typeof(hex)==="undefined")
        return this.hashes[hashType].base64;
    if(hex===true)
        return this.hashes[hashType].hex;
    throw "getPublicKeyHash() called with incorrect parameter hex value";
}

/**
 * Performs mandatory selftests to ensure that JavaScript Public-Key-Pins calculator 
 * works properly with given JavaScript engine.
 * All computed hashes of dummy certificate and dummy CSR are tested.
 * Before creating any pkps.publicKeyPins() objects, this method must have been called.
 *
 * @throws string with textual description of failure.
 */
pkps.doSelfTests = function() {
    try {
        var pkpsTestCrt = new pkps.publicKeyPins(pkps.self_tests_crtPEM);
        var pkpsTestCsr = new pkps.publicKeyPins(pkps.self_tests_csrPEM);
    }
    catch(e) {
        throw "An error occured while computing selftest hashes.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.";
    }
    if(Object.keys(pkpsTestCrt.hashes).length!==4)
        throw "Not all hashes are tested.";
    try {
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
            throw "Selftest hash(es) were computed incorrectly.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.";
        else
            throw "An error occured while accessing selftest hashes.\r\nMost likely your JavaScript engine (e.g. browser) doesn't correctly parse binary strings.";
    }
}
