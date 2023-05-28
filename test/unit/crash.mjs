import { test } from 'node:test';
import { setTimeout } from 'node:timers/promises';
import { ModSecurity, Rules, Transaction } from '../../index.mjs';

/**
 * @returns {Transaction}
 */
const getTx = () => {
    const modsec = new ModSecurity();
    const rules = new Rules();
    rules.add('SecRuleEngine On');
    rules.add(`SecRule REMOTE_ADDR "@ipMatch 192.168.1.1" "phase:1,id:1000,deny,msg:'Blocked IP'"`);

    return new Transaction(modsec, rules);
}

/**
 * @param {Transaction} tx
 */
const runner = (tx) => {
    tx.processConnection('192.168.1.1', 12345, '192.168.1.2', 80);
};

test('it should not crash Node.js', async (t) => {
    if (typeof gc === 'undefined') {
        t.skip('Please rerun with --expose-gc');
        return;
    }

    const tx = getTx();
    gc();
    await setTimeout(100);
    runner(tx);
});
