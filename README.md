# Explainer for the verifyTLSServerCertificate API

This proposal is an early design sketch by ChromeOS Commercial to describe the problem below and solicit
feedback on the proposed solution. It has not been approved to ship in Chrome.

## Participate
https://github.com/explainers-by-googlers/verifyTLSServerCertificateForIWA/issues

## Introduction
This API is currently planned as a part of the [Isolated Web Apps](https://github.com/WICG/isolated-web-apps/blob/main/README.md) proposal 

## Use cases

The primary use case for this API is to enable IWA apps that communicate over raw TCP/UDP using the Direct Sockets API to verify server certificates. Manual verification is challenging and error-prone due to the complexities of certificate management, such as tracking revoked certificates and invalidating compromised authorities. 
Additionally, apps currently cannot verify a certificate against locally installed ones. That’s why they are forced to use less secure options like downloading certificates from some api and comparing them line by line with the server ones

## Alternatives

There's already a chrome extension api for it, we need the same for IWA. 
[browser.platformKeys.verifyTLSServerCertificate](https://developer.chrome.com/docs/extensions/mv2/reference/platformKeys#method-verifyTLSServerCertificate)

## Security and Privacy considerations

The certificate by itself is not trusted input hence an attacker can exploit it to find a vulnerability. As a mitigation our implementation should parse certificates using memory safe language or use a sandboxed process.
On the privacy side, for developers that use this api it is possible to know which certificates are trusted on a user machine. But the same information can be obtained by making fetch requests to HTTPS websites.

## IDL Definitions

The core of this API will be this method

```java
[CallWith=ScriptState]
Promise<undefined> verifyTLSServerCertificate(VerificationDetails details);
```

The `VerificationDetails` are params that specify certificates and hostname that we want to verify.

```java
dictionary VerificationDetails {
  sequence<ArrayBuffer> serverCertificateChain;
  DOMString hostname;
};
```

* Each chain entry in `serverCertificateChain` must be the DER encoding of an X.509 certificate.  
* The first entry must be the server certificate, and each subsequent entry must certify the one preceding it.  
* It is possible to skip intermediate certificates unless the last one has `Authority Information Access` \- CA Issuers field. In such a case it will be downloaded.  
* The `hostname` of the server to verify the certificate for must be present in `serverCertificateChain`.

The result of verification is represented by `Promise<undefined>`

* Successfully resolved promise indicates that trust in the certificate is verified.  
* In case a user has provided an empty certificate chain or one of them is invalid, the Promise will be rejected with `TypeError`.  
* In other cases of promise rejection, it will have `SecurityError` with a string that indicates errors. The error description is for debugging purposes only and may not include all relevant errors. The errors returned may change in future revisions of this API and are not guaranteed to be forwards or backwards compatible. Example of possible errors: `"Certificate validation failed for the following reason(s): COMMON_NAME_INVALID, AUTHORITY_INVALID"`. Where `“COMMON_NAME_INVALID”` means host is not correct. `“AUTHORITY_INVALID”` means the root certificate is not trusted or missed. 

## Simple usage example

Here we read certificates that are bundled with the app and verify them.

```javascript
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
    return await Promise.all(certs.map(readFileAsArrayBuffer));
}

const certificateChain = await getCertificateChain();
try {
    await verifyTLSServerCertificate({
        'hostname': 'example.com',
        'serverCertificateChain': certificateChain
    });
    return 'certificate valid';
} catch (e) {
    return e.message;
}
```

## Example with Direct Sockets and TLS

Here we use a third party library that provides TLS on top of any transport. Unfortunately, the library doesn’t support custom server certificate verification. But there's an unofficial forked version [https://github.com/vkrot-cell/tls](https://github.com/vkrot-cell/tls/tree/main) \- feel free to use it.   
As a transport we will use [Direct Sockets](https://github.com/WICG/direct-sockets/blob/main/docs/explainer.md). 

```javascript
import { makeTLSClient, X509Certificate } from '@reclaimprotocol/tls';

export async function startClient(host: string, port: number) {
    const socket = new TCPSocket(host, port);

    // If rejected by permissions-policy...
    if (!socket) {
        console.log('error to open socket');
        return;
    }

    // Wait for the connection to be established...
    let { readable, writable } = await socket.opened;

    const tlsClient = createTLSClient(writable, host);
    tlsClient.startHandshake();

    const reader = readable.getReader()
    readStream(reader, (data: Uint8Array) => {
        tlsClient.handleReceivedBytes(data);
    })

    // wait for some data from server.
    await delay(2000);
    await reader.cancel()

    // Close the socket. Note that this operation will succeeed if and only if neither readable not writable streams are locked.
    await tlsClient.end();
    await socket.close();
}

async function verifyCertificate(certs: X509Certificate[]) {
    const certs_bytes: Array<ArrayBuffer> = certs.map((cert) => cert.getRawData());

    // call IWA method. If the host is not trusted, it will throw new Error
    await verifyTLSServerCertificate(
        {
            'hostname': 'example.com',
            'serverCertificateChain': certs_bytes
        });
    console.log('server certificate is trusted!');
}

function createTLSClient(writable: WritableStream, host: string) {
    var tlsClient: any = undefined;

    tlsClient = makeTLSClient({
        host,
        verifyServerCertificate: true,
        cipherSuites: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        ],
        supportedProtocolVersions: ['TLS1_2', 'TLS1_3'],
        // write raw bytes to the socket
        async write({ header, content }) {
            // encrypted data is ready to be sent to the server
            const writer = writable.getWriter();
            writer.write(header);
            writer.write(content);
            writer.releaseLock();
        },
        onHandshake() {
            // write encrypted data to the socket
            const encoder = new TextEncoder();
            tlsClient.write(encoder.encode('initial message from client - 1'));
        },
        onApplicationData(data) {
            const decoder = new TextDecoder();
            const messageStr = decoder.decode(data);
            console.log('CLIENT: [tls] data received from the server: ' + messageStr);
        },
        onTlsEnd(error) {
           console.info('CLIENT: TLS connect ended: ', error);
        },
        async customServerCertificateVerification(_host: string, certificates: X509Certificate[]) {
            await verifyCertificate(certificates);
        },
    });

    return tlsClient;
}

async function readStream(
    reader: ReadableStreamDefaultReader,
    cb: (value: Uint8Array) => void,
): Promise<void> {
    // Read from the socket until it's closed
    while (reader) {
        // Wait for the next chunk
        const { value, done } = await reader.read();

        // Send the chunk to the callback
        if (value) {
            cb(value);
        }
        // Release the reader if we're done
        if (done) {
            reader.releaseLock();
            break;
        }
    }
}

function delay(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
```
