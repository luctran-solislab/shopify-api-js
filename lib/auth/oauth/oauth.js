"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callback = exports.begin = void 0;
const tslib_1 = require("tslib");
const crypto_1 = tslib_1.__importDefault(require("crypto"));
const uuid_1 = require("uuid");
const isbot_1 = tslib_1.__importDefault(require("isbot"));
const processed_query_1 = tslib_1.__importDefault(require("../../utils/processed-query"));
const ShopifyErrors = tslib_1.__importStar(require("../../error"));
const hmac_validator_1 = require("../../utils/hmac-validator");
const shop_validator_1 = require("../../utils/shop-validator");
const session_1 = require("../../session/session");
const session_utils_1 = require("../../session/session-utils");
const http_client_1 = require("../../clients/http_client/http_client");
const types_1 = require("../../clients/http_client/types");
const http_1 = require("../../../runtime/http");
const logger_1 = require("../../logger");
const types_2 = require("./types");
const safe_compare_1 = require("./safe-compare");
const logForBot = ({ request, log, func }) => {
    log.debug(`Possible bot request to auth ${func}: `, {
        userAgent: request.headers['User-Agent'],
    });
};
function begin(config) {
    return (_a) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        var { shop, callbackPath, isOnline } = _a, adapterArgs = tslib_1.__rest(_a, ["shop", "callbackPath", "isOnline"]);
        throwIfCustomStoreApp(config.isCustomStoreApp, 'Cannot perform OAuth for private apps');
        const log = (0, logger_1.logger)(config);
        log.info('Beginning OAuth', { shop, isOnline, callbackPath });
        const request = yield (0, http_1.abstractConvertRequest)(adapterArgs);
        const response = yield (0, http_1.abstractConvertIncomingResponse)(adapterArgs);
        if ((0, isbot_1.default)(request.headers['User-Agent'])) {
            logForBot({ request, log, func: 'begin' });
            response.statusCode = 410;
            return (0, http_1.abstractConvertResponse)(response, adapterArgs);
        }
        const cleanShop = (0, shop_validator_1.sanitizeShop)(config)(shop, true);
        const apiKey = config.apiKey;
        const hashkey = isOnline ? `online_${apiKey}_sls` : `offline_${apiKey}_sls`;
        const hash = crypto_1.default.createHash('sha256');
        const hashedShop = hash.update(cleanShop + hashkey).digest('hex');
        const state = isOnline ? `online_${hashedShop}` : `offline_${hashedShop}`;
        const query = {
            client_id: config.apiKey,
            scope: config.scopes.toString(),
            redirect_uri: `${config.hostScheme}://${config.hostName}${callbackPath}`,
            state,
            'grant_options[]': isOnline ? 'per-user' : '',
        };
        const processedQuery = new processed_query_1.default();
        processedQuery.putAll(query);
        const redirectUrl = `https://${cleanShop}/admin/oauth/authorize${processedQuery.stringify()}`;
        response.statusCode = 302;
        response.statusText = 'Found';
        response.headers = Object.assign(Object.assign({}, response.headers), { Location: redirectUrl });
        log.debug(`OAuth started, redirecting to ${redirectUrl}`, { shop, isOnline });
        return (0, http_1.abstractConvertResponse)(response, adapterArgs);
    });
}
exports.begin = begin;
function callback(config) {
    return function callback(_a) {
        var _b;
        var adapterArgs = tslib_1.__rest(_a, []);
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            throwIfCustomStoreApp(config.isCustomStoreApp, 'Cannot perform OAuth for private apps');
            const log = (0, logger_1.logger)(config);
            const request = yield (0, http_1.abstractConvertRequest)(adapterArgs);
            const query = new URL(request.url, `${config.hostScheme}://${config.hostName}`).searchParams;
            const shop = query.get('shop');
            const response = {};
            if ((0, isbot_1.default)(request.headers['User-Agent'])) {
                logForBot({ request, log, func: 'callback' });
                throw new ShopifyErrors.BotActivityDetected('Invalid OAuth callback initiated by bot');
            }
            log.info('Completing OAuth', { shop });
            const cookies = new http_1.Cookies(request, response, {
                keys: [config.apiSecretKey],
                secure: true,
            });
            const cleanShop = (0, shop_validator_1.sanitizeShop)(config)(query.get('shop'), true);
            const isOnline = (_b = query.get('state')) === null || _b === void 0 ? void 0 : _b.startsWith('online_');
            const apiKey = config.apiKey;
            const hashkey = isOnline ? `online_${apiKey}_sls` : `offline_${apiKey}_sls`;
            const hash = crypto_1.default.createHash('sha256');
            const hashedShop = hash.update(cleanShop + hashkey).digest('hex');
            const state = isOnline ? `online_${hashedShop}` : `offline_${hashedShop}`;
            const authQuery = Object.fromEntries(query.entries());
            if (!(yield validQuery({ config, query: authQuery, state }))) {
                log.error('Invalid OAuth callback', { shop, state });
                throw new ShopifyErrors.InvalidOAuthError('Invalid OAuth callback.');
            }
            log.debug('OAuth request is valid, requesting access token', { shop });
            const body = {
                client_id: config.apiKey,
                client_secret: config.apiSecretKey,
                code: query.get('code'),
            };
            const postParams = {
                path: '/admin/oauth/access_token',
                type: types_1.DataType.JSON,
                data: body,
            };
            const HttpClient = (0, http_client_1.httpClientClass)(config);
            const client = new HttpClient({ domain: cleanShop });
            const postResponse = yield client.post(postParams);
            const session = createSession({
                postResponse,
                shop: cleanShop,
                state,
                config,
            });
            if (!config.isEmbeddedApp) {
                yield cookies.setAndSign(types_2.SESSION_COOKIE_NAME, session.id, {
                    expires: session.expires,
                    sameSite: 'lax',
                    secure: true,
                    path: '/',
                });
            }
            return {
                headers: (yield (0, http_1.abstractConvertHeaders)(cookies.response.headers, adapterArgs)),
                session,
            };
        });
    };
}
exports.callback = callback;
function validQuery({ config, query, state, }) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        return ((yield (0, hmac_validator_1.validateHmac)(config)(query)) &&
            (0, safe_compare_1.safeCompare)(query.state, state));
    });
}
function createSession({ config, postResponse, shop, state, }) {
    const associatedUser = postResponse.body
        .associated_user;
    const isOnline = Boolean(associatedUser);
    (0, logger_1.logger)(config).info('Creating new session', { shop, isOnline });
    if (isOnline) {
        let sessionId;
        const responseBody = postResponse.body;
        const { access_token, scope } = responseBody, rest = tslib_1.__rest(responseBody, ["access_token", "scope"]);
        const sessionExpiration = new Date(Date.now() + responseBody.expires_in * 1000);
        if (config.isEmbeddedApp) {
            sessionId = (0, session_utils_1.getJwtSessionId)(config)(shop, `${rest.associated_user.id}`);
        }
        else {
            sessionId = (0, uuid_1.v4)();
        }
        return new session_1.Session({
            id: sessionId,
            shop,
            state,
            isOnline,
            accessToken: access_token,
            scope,
            expires: sessionExpiration,
            onlineAccessInfo: rest,
        });
    }
    else {
        const responseBody = postResponse.body;
        return new session_1.Session({
            id: (0, session_utils_1.getOfflineId)(config)(shop),
            shop,
            state,
            isOnline,
            accessToken: responseBody.access_token,
            scope: responseBody.scope,
        });
    }
}
function throwIfCustomStoreApp(isCustomStoreApp, message) {
    if (isCustomStoreApp) {
        throw new ShopifyErrors.PrivateAppError(message);
    }
}
//# sourceMappingURL=oauth.js.map