import { describe, it } from 'node:test';
import { match, strictEqual } from 'node:assert/strict';
import { ModSecurity, Rules, Transaction } from '../index.mjs';

describe('ModSecurity', () => {
    describe('setLogCallback', () => {
        it('should set a logging callabck', () => {
            const modsec = new ModSecurity();
            /** @type {string|null} */
            let actualMessage = null;

            modsec.setLogCallback((message) => {
                actualMessage = message;
            });

            const rules = new Rules();
            rules.add(`SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "phase:1,id:1000,log,msg:'Blocked IP'"`);

            const tx = new Transaction(modsec, rules);
            let res = tx.processConnection('127.0.0.1', 12345, '127.0.0.1', 80);
            strictEqual(res, true);
            res = tx.processRequestHeaders();
            strictEqual(res, true);
            // @ts-ignore -- false positive; `match` accepts anything
            match(actualMessage, /Blocked IP/);
        });

        it('should overwrite the old callback', () => {
            const modsec = new ModSecurity();
            /** @type {string|null} */
            let actualMessage = null;

            modsec.setLogCallback(() => {
                actualMessage = 'FAIL';
            });

            modsec.setLogCallback((message) => {
                actualMessage = message;
            });

            const rules = new Rules();
            rules.add(`SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "phase:1,id:1000,log,msg:'Blocked IP'"`);

            const tx = new Transaction(modsec, rules);
            let res = tx.processConnection('127.0.0.1', 12345, '127.0.0.1', 80);
            strictEqual(res, true);
            res = tx.processRequestHeaders();
            strictEqual(res, true);
            // @ts-ignore -- false positive; `match` accepts anything@ts-ignore
            match(actualMessage, /Blocked IP/);
        });
    })
});
