# Explainer for the verifyTLSServerCertificate API

This proposal is an early design sketch by ChromeOS Commercial to describe the problem below and solicit
feedback on the proposed solution. It has not been approved to ship in Chrome.

## Participate
- https://github.com/explainers-by-googlers/verifyTLSServerCertificateForIWA/issues
- [Discussion forum]

## Introduction

[The "executive summary" or "abstract".
Explain in a few sentences what the goals of the project are,
and a brief overview of how the solution works.
This should be no more than 1-2 paragraphs.]

## Use cases

The initial motivating use case is to add ability for we apps that use Direct Sockets API to communicate over raw TCP/UDP to
verify server certificates. Doing so manually is hard and prone to error, because there are many nuances in certificate management: track revoked certificates, invalidate compromised authorities and so on.

### Alternatives

There's already an extension api for it - `browser.platformKeys.verifyTLSServerCertificate`
https://developer.chrome.com/docs/extensions/mv2/reference/platformKeys#method-verifyTLSServerCertificate

### IDL Definitions

``` java
[CallWith=ScriptState]
Promise<VerificationResult> verifyTLSServerCertificate(VerificationDetails details);

dictionary VerificationDetails {
  // Each chain entry must be the DER encoding of a X.509 certificate, the
  // first entry must be the server certificate and each entry must certify
  // the entry preceding it.
  sequence<ArrayBuffer> serverCertificateChain;

  // The hostname of the server to verify the certificate for, e.g. the server
  // that presented the <code>serverCertificateChain</code>.
  DOMString hostname;
};

dictionary VerificationResult {
  // The result of the trust verification: true if trust for the given
  // verification details could be established and false if trust is rejected
  // for any reason.
  boolean trusted;

  // If the trust verification failed, this array contains the errors reported
  // by the underlying network layer. Otherwise, this array is empty.
  //
  // <strong>Note:</strong> This list is meant for debugging only and may not
  // contain all relevant errors. The errors returned may change in future
  // revisions of this API, and are not guaranteed to be forwards or backwards
  // compatible.
  sequence<DOMString> debug_errors;
};
```

### Examples
<details>
<summary>Learn more about using verifyTLSServerCertificate.</summary>

``` js
async function readFileAsArrayBuffer(filePath) {
    const response = await fetch(filePath);

    if (!response.ok) {
      throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return arrayBuffer;
  }

  async function getCertificateChain() {
    const certs = ['leaf_cert.der', 'interim_cert.der'];
    return await Promise.all(Array.prototype.map.call(certs, cert =>    readFileAsArrayBuffer(cert)));
  }
  const certificateChain = await getCertificateChain();
  const certResult = await verifyTLSServerCertificate(
   {
      'hostname': 'example.com',
      'serverCertificateChain': certificateChain
    });
  return JSON.stringify(certResult);
```
</details>
