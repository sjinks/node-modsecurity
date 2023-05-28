import { describe, it } from 'node:test';
import { match, strictEqual } from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import express, { raw } from 'express';
import request from 'supertest';
import { ModSecurity, Rules, Transaction } from '../../index.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

class InterventionError extends Error {
    /**
     * @param {import('../../index.mjs').Intervention} intervention
     */
    constructor(intervention) {
        super('Intervention');
        this.name = 'InterventionError';
        this.intervention = intervention;
    }
}

class UnexpectedError extends Error {
    constructor() {
        super('Unexpected');
        this.name = 'UnexpectedError';
    }
}

const checkIntervention = (val) => {
    if (typeof(val) === 'object') {
        throw new InterventionError(val);
    }

    if (false === val) {
        throw new UnexpectedError();
    }
};

function createModSecurityMiddleware() {
    const modsec = new ModSecurity();
    const rules = new Rules();
    rules.loadFromFile(join(__dirname, '..', 'fixtures', 'integration.conf'));

    /**
     * @param {express.Request} request
     * @param {express.Response} response
     * @param {express.NextFunction} next
     */
    return (request, response, next) => {
        const tx = new Transaction(modsec, rules);
        let res;

        response.locals.tx = tx;

        res = tx.processConnection(request.ip, request.socket.remotePort || 0, request.socket.localAddress || '', request.socket.localPort || 0);
        checkIntervention(res);

        res = tx.processURI(request.url, request.method, request.httpVersion);
        checkIntervention(res);

        /** @type {string|null} */
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
        checkIntervention(res);

        if (Buffer.isBuffer(request.body)) {
            res = tx.appendRequestBody(request.body);
            checkIntervention(res);
        }

        res = tx.processRequestBody();
        checkIntervention(res);

        return next();
    };
}

/**
 * @param {express.Request} _request
 * @param {express.Response} response
 * @param {express.NextFunction} next
 */
function notFoundHandler(_request, response, next) {
    if (!response.headersSent) {
        response.status(404).json({
            status: 404,
            message: 'Not found',
        });
    }

    next();
}

/**
 * @param {express.Request} _request
 * @param {express.Response} response
 * @param {express.NextFunction} next
 */
function modSecLogging(_request, response, next) {
    const tx = response.locals.tx;
    if (tx instanceof Transaction) {
        tx.processLogging();
    }

    delete response.locals.tx;
    next();
}

/**
 * @param {Error} error
 * @param {express.Request} request
 * @param {express.Response} response
 * @param {express.NextFunction} next
 */
function errorHandler(error, request, response, next) {
    if (response.headersSent) {
        return next(error);
    }

    if (error instanceof InterventionError) {
        response.status(error.intervention.status);
        if (error.intervention.url) {
            response.redirect(error.intervention.status, error.intervention.url);
        } else {
            response.json({
                intervention: true,
                status: error.intervention.status,
                message: error.intervention.log,
            });
        }
    } else if (error instanceof UnexpectedError) {
        response.status(500).json({
            status: 500,
            unexpected: true,
            message: error.message,
        });
    } else {
        response.status(500).json({
            status: 500,
            unknown: true,
            message: error.message,
        });
    }
}

/**
 * @param {express.RequestHandler} [handler]
 * @returns {express.Express}
 */
function createApp(handler) {
    const app = express();
    app.enable('trust proxy');
    app.use(raw({ type: '*/*' }));
    app.use(createModSecurityMiddleware());

    if (handler) {
        app.use(handler);
    }

    app.use(notFoundHandler);
    app.use(modSecLogging);
    app.use(errorHandler);
    return app;
}

describe('Integration testing', () => {
    it('should reject blocked IPs', () => {
        const app = createApp();
        return request(app)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .set('Accept', 'application/json')
            .expect(403)
            .expect('Content-Type', /json/)
            .expect((res) => {
                strictEqual(res.body.intervention, true);
                strictEqual(res.body.status, 403);
                match(res.body.message, /Blocked IP/);
            });
    });

    it('should reject disallowed methods', () => {
        const app = createApp();
        return request(app)
            .trace('/')
            .set('X-Forwarded-For', '192.168.0.1')
            .set('Accept', 'application/json')
            .expect(405)
            .expect('Content-Type', /json/)
            .expect((res) => {
                strictEqual(res.body.intervention, true);
                strictEqual(res.body.status, 405);
                match(res.body.message, /Method is not allowed by policy/);
            });
    });

    it('should reject disallowed headers', () => {
        const app = createApp();
        return request(app)
            .get('/')
            .set('X-Forwarded-For', '192.168.0.1')
            .set('Accept', 'application/json')
            .set('Crash', 'boom')
            .expect(400)
            .expect('Content-Type', /json/)
            .expect((res) => {
                strictEqual(res.body.intervention, true);
                strictEqual(res.body.status, 400);
                match(res.body.message, /Crash header not allowed/);
            });
    });

    it('should reject long request body', () => {
        const app = createApp();
        return request(app)
            .post('/')
            .set('X-Forwarded-For', '192.168.0.1')
            .set('Accept', 'application/json')
            .set('Content-Type', 'text/plain')
            .send('a'.repeat(2000))
            .expect(403)
            .expect('Content-Type', /json/)
            .expect((res) => {
                strictEqual(res.body.intervention, true);
                strictEqual(res.body.status, 403);
                match(res.body.message, /Request body limit/);
            });
    });

    it('should reject disallowed body', () => {
        const app = createApp();
        return request(app)
            .post('/api')
            .set('X-Forwarded-For', '192.168.0.1')
            .set('Accept', 'application/json')
            .set('Content-Type', 'text/plain')
            .send('xxx')
            .expect(302)
            .expect('Location', 'https://example.com/forbidden.html');
    });

    it('should allow normal requests', () => {
        /**
         * @param {express.Request} _req
         * @param {express.Response} res
         * @param {express.NextFunction} next
         */
        const app = createApp((_req, res, next) => {
            res.json({ ok: true }).end();
            next();
        });

        return request(app)
            .get('/')
            .set('X-Forwarded-For', '192.168.0.1')
            .set('Accept', 'application/json')
            .expect(200)
            .expect({ ok: true });
    });
});
