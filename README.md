# node-modsecurity

A [ModSecurity](https://github.com/SpiderLabs/ModSecurity#readme) connector for Node.js

## Prerequisites

Because this library provides Node.js bindings to `libmodsecurity`, `libmodsecurity` along with its development files has to be installed.

See: https://pkgs.org/search/?q=libmodsecurity

### Ubuntu

```sh
sudo apt-get install -y libmodsecurity3 libmodsecurity-dev
```

### CentOS

```sh
sudo yum -y install epel-release
sudo yum -y install libmodsecurity libmodsecurity-devel
```

### MacOS

TBD

### Windows

[Not supported](https://github.com/SpiderLabs/ModSecurity#windows)

### Caveats

Old versions of libmodsecurity are sometimes buggy: for example, libmodsecurity up to 3.0.8 (since at least 3.0.6) may [crash](https://github.com/SpiderLabs/ModSecurity/issues/2872)
if you forget to call to `Transaction::processConnection()` or `Transaction::processURI()`; libmodsecurity 3.0.6 leaks memory.

Theerefore, it is recommended to install (or, more likely, build) the latest version of libmodsecurity yourself. The [official documentation](https://github.com/SpiderLabs/ModSecurity#compilation)
and [project Wiki](https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes-for-v3.x) provide instructions on how to compile the library.

As of the time of writing, libmodsecurity 3.0.9 seems to be OK: my tests did not find memory leaks nor was I able to crash it from Node.js.

## Installation

(TBD; the library has not been published to NPM yet)

```sh
npm install modsecurity
```

## Usage

TBD; please see [this](https://github.com/sjinks/node-modsecurity/blob/245049f87b276fd56c1493b37afa437d04613e72/test/integration/lifecycle.mjs#L39-L85) for usage example.

tl;dr:
```js
import { createServer } from 'node:http';
import { ModSecurity, Rules, Transaction } from 'modsecurity';

const modsec = new ModSecurity();
// Optional: set logging callback:
modsec.setLogCallback((message) => console.log(message));

const rules = new Rules();
rules.loadFromFile('rules.conf');

const server = createServer((request, response) => {
    const tx = new Transaction(modsec, rules);
    let res;

    res = tx.processConnection(request.socket.remoteAddr, request.socket.remotePort, request.socket.localAddress, request.socket.localPort);
    if (typeof res === 'object') {
        return processIntervention(res, response, tx);
    }

    if (false === res) {
        // modsecurity returned an error
    }

    res = tx.processURI(request.url, request.method, request.httpVersion);
    if (typeof res === 'object') {
        return processIntervention(res, response, tx);
    }

    let key = null;
    for (const v of request.rawHeaders) {
        if (key === null) {
            key = v;
        } else {
            tx.addRequestHeader(key, v);
            key = null;
        }
    }

    res = tx.processRequestHeaders();
    if (typeof res === 'object') {
        return processIntervention(res, response, tx);
    }
        
    if (Buffer.isBuffer(request.body)) {
        res = tx.appendRequestBody(request.body);
        if (typeof res === 'object') {
            return processIntervention(res, response, tx);
        }
    }
            
    res = tx.processRequestBody();
    if (typeof res === 'object') {
        return processIntervention(res, response, tx);
    }

    // Handle request here

    tx.processLogging();
});

function processIntervention(intervention, response, tx) {
    response.statusCode = intervention.status;
    if (intervention.url) {
        response.setHeader('Location', intervention.url);
    }

    // intervention.log contains additional information

    response.end();
    tx.processLogging();
}

server.listen(3000);
```
