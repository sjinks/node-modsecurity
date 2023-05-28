import { describe, it } from 'node:test';
import { strictEqual, throws } from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Rules } from '../../index.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('Rules', () => {
    describe('constructor', () => {
        it('should create an empty set of rules', () => {
            const rules = new Rules();
            strictEqual(rules.length, 0);
        });
    });

    describe('loadFromFile', () => {
        it('should load rules from a file', () => {
            const rules = new Rules();
            const result = rules.loadFromFile(join(__dirname, '..', 'fixtures', 'valid-rules.conf'));
            strictEqual(result, true);
            strictEqual(rules.length, 1);
        });

        it('should fail on invalid rules', () => {
            const rules = new Rules();
            throws(() => rules.loadFromFile(join(__dirname, '..', 'fixtures', 'invalid-rules.conf')), /Invalid input/);
        });

        it('should fail on non-existing file', () => {
            const rules = new Rules();
            throws(() => rules.loadFromFile(join(__dirname, '..', 'fixtures', 'this-file-does-not-exist')), /Failed to open/);
        });
    });

    describe('add', () => {
        it('should add valid rules', () => {
            const rules = new Rules();
            const result = rules.add(`SecRule REMOTE_ADDR "@ipMatch 192.168.1.1" "phase:1,id:1000,deny,msg:'Blocked IP'"`);
            strictEqual(result, true);
            strictEqual(rules.length, 1);
        });

        it('should process valid directives', () => {
            const rules = new Rules();
            const result = rules.add('SecRuleEngine On');
            strictEqual(result, true);
            strictEqual(rules.length, 0);
        });

        it('should process empty input', () => {
            const rules = new Rules();
            const result = rules.add('');
            strictEqual(result, true);
            strictEqual(rules.length, 0);
        });

        it('should process comments', () => {
            const rules = new Rules();
            const result = rules.add('# comment');
            strictEqual(result, true);
            strictEqual(rules.length, 0);
        });

        it('should fail on invalid rules', () => {
            const rules = new Rules();
            throws(() => rules.add('waka waka'), /Invalid input/);
        });
    });

    describe('merge', () => {
        it('should merge two rulesets', () => {
            const lhs = new Rules();
            const rhs = new Rules();

            lhs.add(`SecRule REMOTE_ADDR "@ipMatch 192.168.1.1" "phase:1,id:1000,deny,msg:'Blocked IP'"`);
            rhs.add(`SecRule REQUEST_METHOD "^(?:CONNECT|TRACE)$" "phase:2,id:50,deny,status:405,msg:'Method is not allowed by policy'"`);

            const result = lhs.merge(rhs);
            strictEqual(result, true);
            strictEqual(lhs.length, 2);
            strictEqual(rhs.length, 1);
        });

        it('should fail on duplicate rules', () => {
            const lhs = new Rules();
            const rhs = new Rules();
            const rule = `SecRule REMOTE_ADDR "@ipMatch 192.168.1.1" "phase:1,id:1000,deny,msg:'Blocked IP'"`;

            lhs.add(rule);
            rhs.add(rule);

            throws(() => lhs.merge(rhs), /duplicated/);
        });

        it('should allow to merge empty rulesets', () => {
            const lhs = new Rules();
            const rhs = new Rules();
            const result = lhs.merge(rhs);
            strictEqual(result, true);
            strictEqual(lhs.length, 0);
            strictEqual(rhs.length, 0);
        });

        it('should fail if the argument is not Rules instance', () => {
            const rules = new Rules();
            // @ts-ignore -- intentionally passing invalid argument
            throws(() => rules.merge({}), TypeError);
        });
    });
});
