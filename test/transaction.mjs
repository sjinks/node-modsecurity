import { describe, it } from 'node:test';
import { match, strictEqual, throws } from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ModSecurity, Rules, Transaction } from '../index.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * @param {*} something
 * @returns {void}
 */
function assertIsIntervention(something) {
    strictEqual(typeof something, 'object');
    strictEqual(something.constructor.name, 'Intervention');
}

/**
 * @param {*} intervention
 * @param {number} status
 * @param {string|null} url
 * @param {RegExp} log
 * @param {boolean} disruptive
 * @returns {void}
 */
function checkIntervention(intervention, status, url, log, disruptive) {
    assertIsIntervention(intervention);
    strictEqual(intervention.status, status);
    strictEqual(intervention.url, url);
    match(intervention.log, log);
    strictEqual(intervention.disruptive, disruptive);
}

describe('Transaction', () => {
    it('should work', () => {
        const modsec = new ModSecurity();
        const rules = new Rules();
        const tx = new Transaction(modsec, rules);
        let res;

        res = tx.processConnection('192.168.1.1', 12345, '192.168.1.2', 80);
        strictEqual(res, true);

        res = tx.processURI('/index.html', 'CONNECT', '1.1');
        strictEqual(res, true);

        res = tx.processRequestHeaders();
        strictEqual(res, true);

        res = tx.processRequestBody();
        strictEqual(res, true);

        res = tx.processResponseHeaders(200, 'HTTP/1.1');
        strictEqual(res, true);

        res = tx.processResponseBody();
        strictEqual(res, true);

        res = tx.processLogging();
        strictEqual(res, true);
    });

    describe('constructor', () => {
        const table = [
            ['invoked with no arguments', []],
            ['the first argument is not ModSecurity instance', [null, new Rules()]],
            ['the second argument is not Rules instance', [new ModSecurity(), {}]],
        ];

        for (const [name, args] of table) {
            it(`should fail when ${name}`, () => {
                // @ts-ignore -- intentionally passing invalid arguments
                throws(() => new Transaction(args[0], args[1]), TypeError);
            });
        }
    });

    describe('processConnection', () => {
        it('should return true if everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processConnection('127.0.0.1', 12345, '127.0.0.1', 80);
            strictEqual(res, true);
        });

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add(`SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "phase:0,id:1000,nolog,deny,msg:'Blocked IP'"`);

            const tx = new Transaction(new ModSecurity(), rules);
            const res = tx.processConnection('127.0.0.1', 12345, '127.0.0.1', 80);
            checkIntervention(res, 403, null, /msg "Blocked IP"/, true);
        });
    });

    describe('processConnection', () => {
        it('should return true if everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processURI('/', 'GET', 'HTTP/1.1');
            strictEqual(res, true);
        });
    });

    describe('addRequestHeader', () => {
        const table_1 = [
            ['(string, string)', 'Test', 'Value'],
            ['(string, buffer)', 'Test', Buffer.from('Value')],
            ['(buffer, string)', Buffer.from('Test'), 'Value'],
            ['(buffer, buffer)', Buffer.from('Test'), Buffer.from('Value')],
        ];

        for (const [name, key, value] of table_1) {
            it(`should work with ${name}`, () => {
                const tx = new Transaction(new ModSecurity(), new Rules());
                const res = tx.addRequestHeader(key, value);
                strictEqual(res, true);
            });
        }

        /**
         * @type {[string[], boolean][]}
         */
        const table_2 = [
            [[], false],
            [['Header'], false],
            [['Header', 'Value', 'Extra'], true],
        ];

        for (const [args, outcome] of table_2) {
            it(`should return ${outcome} when called with ${args.length} arguments`, () => {
                const tx = new Transaction(new ModSecurity(), new Rules());
                // @ts-ignore -- cannot make a TS cast in JS‌ mode
                const res = tx.addRequestHeader(...args);
                strictEqual(res, outcome);
            });
        }
    });

    describe('processRequestHeaders', () => {
        it('should return true if everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processRequestHeaders();
            strictEqual(res, true);
        });

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add(`SecRule &REQUEST_HEADERS:Authorization "@gt 0" "id:1001,phase:1,deny,status:400,msg:'Authorization header not allowed'"`);

            const tx = new Transaction(new ModSecurity(), rules);
            tx.addRequestHeader('Authorization', 'broken');
            const res = tx.processRequestHeaders();
            checkIntervention(res, 400, null, /msg "Authorization header not allowed"/, true);
        });
    });

    describe('appendRequestBody', () => {
        it('should return false when called with no arguments', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            // @ts-ignore -- intentionally passing invalid argument
            const res = tx.appendRequestBody();
            strictEqual(res, false);
        });

        it('should throw when its argument is not a String or Buffer', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            // @ts-ignore -- intentionally passing invalid argument
            throws(() => tx.appendRequestBody({}), TypeError);
        });

        const table = [
            ['(string)', 'test'],
            ['(buffer)', Buffer.from('test')],
        ];

        for (const [what, body] of table) {
            it(`should accept ${what} as request body`, () => {
                const tx = new Transaction(new ModSecurity(), new Rules());
                const res = tx.appendRequestBody(body);
                strictEqual(res, true);
            });
        }

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add('SecRequestBodyLimit 1');
            rules.add('SecRequestBodyLimitAction Reject')

            const tx = new Transaction(new ModSecurity(), rules);
            const res = tx.appendRequestBody('test');
            checkIntervention(res, 403, null, /Request body limit/, true);
        });

        it('should append to the request body when called multiple times', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add('SecRequestBodyLimit 3');
            rules.add('SecRequestBodyLimitAction Reject')

            const tx = new Transaction(new ModSecurity(), rules);
            let res = tx.appendRequestBody('te');
            strictEqual(res, true);
            res = tx.appendRequestBody(Buffer.from('st'));
            checkIntervention(res, 403, null, /Request body limit/, true);
        });
    });

    describe('requestBodyFromFile', () => {
        it('should return false when called with no arguments', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            // @ts-ignore -- intentionally passing invalid argument
            const res = tx.requestBodyFromFile();
            strictEqual(res, false);
        });

        it('should return false when the file does not exist', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.requestBodyFromFile(join(__dirname, 'fixtures', 'this-file-does-not-exist'));
            strictEqual(res, false);
        });

        it('should return true when everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.requestBodyFromFile(join(__dirname, 'fixtures', 'request-body.txt'));
            strictEqual(res, true);
        });

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add('SecRequestBodyLimit 1');
            rules.add('SecRequestBodyLimitAction Reject')

            const tx = new Transaction(new ModSecurity(), rules);
            const res = tx.requestBodyFromFile(join(__dirname, 'fixtures', 'request-body.txt'));
            checkIntervention(res, 403, null, /Request body limit/, true);
        });
    });

    describe('processRequestBody', () => {
        it('should return true when everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processRequestBody();
            strictEqual(res, true);
        });

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add(`SecRule REQUEST_BODY "lunchrast" "phase:2,id:75,deny,status:403,msg:'Argh!'"`)

            const tx = new Transaction(new ModSecurity(), rules);
            let res = tx.requestBodyFromFile(join(__dirname, 'fixtures', 'request-body.txt'));
            strictEqual(res, true);
            res = tx.processRequestBody();
            checkIntervention(res, 403, null, /Argh!/, true);
        });
    });

    describe('addResponseHeader', () => {
        const table_1 = [
            ['(string, string)', 'Test', 'Value'],
            ['(string, buffer)', 'Test', Buffer.from('Value')],
            ['(buffer, string)', Buffer.from('Test'), 'Value'],
            ['(buffer, buffer)', Buffer.from('Test'), Buffer.from('Value')],
        ];

        for (const [name, key, value] of table_1) {
            it(`should work with ${name}`, () => {
                const tx = new Transaction(new ModSecurity(), new Rules());
                const res = tx.addResponseHeader(key, value);
                strictEqual(res, true);
            });
        }

        /**
         * @type {[string[], boolean][]}
         */
        const table_2 = [
            [[], false],
            [['Header'], false],
            [['Header', 'Value', 'Extra'], true],
        ];

        for (const [args, outcome] of table_2) {
            it(`should return ${outcome} when called with ${args.length} arguments`, () => {
                const tx = new Transaction(new ModSecurity(), new Rules());
                // @ts-ignore -- cannot make a TS cast in JS‌ mode
                const res = tx.addResponseHeader(...args);
                strictEqual(res, outcome);
            });
        }
    });

    describe('processResponseHeaders', () => {
        it('should return true if everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processResponseHeaders(200, 'HTTP/1.1');
            strictEqual(res, true);
        });

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add(`SecRule &RESPONSE_HEADERS:Secret "@gt 0" "id:1001,phase:3,redirect:http://www.example.com/,msg:'Secret header leaked'"`);

            const tx = new Transaction(new ModSecurity(), rules);
            tx.addResponseHeader('Secret', 'pa$$w0rd');
            const res = tx.processResponseHeaders(200, 'HTTP/1.1');
            checkIntervention(res, 302, 'http://www.example.com/', /msg "Secret header leaked"/, true);
        });
    });

    describe('updateStatusCode', () => {
        it('should work', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add('SecResponseBodyAccess On');
            rules.add(`SecRule RESPONSE_STATUS "204" "id:80,phase:4,deny,msg:'Grrr'"`);

            const tx = new Transaction(new ModSecurity(), rules);
            let res = tx.processResponseHeaders(200, 'HTTP/1.1');
            strictEqual(res, true);
            res = tx.updateStatusCode(204);
            strictEqual(res, true);

            res = tx.processResponseBody();
            checkIntervention(res, 403, null, /msg "Grrr"/, true);
        });
    });


    describe('processReponseBody', () => {
        it('should return true when everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processResponseBody();
            strictEqual(res, true);
        });

        it('should return Intervention if required', () => {
            const rules = new Rules();
            rules.add('SecRuleEngine On');
            rules.add('SecResponseBodyAccess On');
            rules.add(`SecRule RESPONSE_BODY "lunchrast" "phase:4,id:75,deny,status:500,msg:'Argh!'"`)

            const tx = new Transaction(new ModSecurity(), rules);
            let res = tx.appendResponseBody('För livet är ingen lunchrast, livet är inte lätt');
            strictEqual(res, true);
            res = tx.processResponseBody();
            checkIntervention(res, 500, null, /Argh!/, true);
        });
    });

    describe('processLogging', () => {
        it('should return true when everything is OK', () => {
            const tx = new Transaction(new ModSecurity(), new Rules());
            const res = tx.processLogging();
            strictEqual(res, true);
        });
    });
});
