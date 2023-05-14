import crypto from 'crypto';

import {v4 as uuidv4} from 'uuid';
import isbot from 'isbot';

import ProcessedQuery from '../../utils/processed-query';
import {ConfigInterface} from '../../base-types';
import * as ShopifyErrors from '../../error';
import {validateHmac} from '../../utils/hmac-validator';
import {sanitizeShop} from '../../utils/shop-validator';
import {Session} from '../../session/session';
import {getJwtSessionId, getOfflineId} from '../../session/session-utils';
import {httpClientClass} from '../../clients/http_client/http_client';
import {DataType, RequestReturn} from '../../clients/http_client/types';
import {
  abstractConvertRequest,
  abstractConvertIncomingResponse,
  abstractConvertResponse,
  abstractConvertHeaders,
  AdapterResponse,
  AdapterHeaders,
  Cookies,
  NormalizedResponse,
  NormalizedRequest,
} from '../../../runtime/http';
import {logger, ShopifyLogger} from '../../logger';

import {
  SESSION_COOKIE_NAME,
  BeginParams,
  CallbackParams,
  AuthQuery,
  AccessTokenResponse,
  OnlineAccessResponse,
  OnlineAccessInfo,
} from './types';
import {safeCompare} from './safe-compare';

export interface CallbackResponse<T = AdapterHeaders> {
  headers: T;
  session: Session;
}

interface BotLog {
  request: NormalizedRequest;
  log: ShopifyLogger;
  func: string;
}

const logForBot = ({request, log, func}: BotLog) => {
  log.debug(`Possible bot request to auth ${func}: `, {
    userAgent: request.headers['User-Agent'],
  });
};

export function begin(config: ConfigInterface) {
  return async ({
    shop,
    callbackPath,
    isOnline,
    ...adapterArgs
  }: BeginParams): Promise<AdapterResponse> => {
    throwIfCustomStoreApp(
      config.isCustomStoreApp,
      'Cannot perform OAuth for private apps',
    );

    const log = logger(config);
    log.info('Beginning OAuth', {shop, isOnline, callbackPath});

    const request = await abstractConvertRequest(adapterArgs);
    const response = await abstractConvertIncomingResponse(adapterArgs);

    if (isbot(request.headers['User-Agent'])) {
      logForBot({request, log, func: 'begin'});
      response.statusCode = 410;
      return abstractConvertResponse(response, adapterArgs);
    }

    const cleanShop = sanitizeShop(config)(shop, true)!;
    const apiKey = config.apiKey;
    const hashkey = isOnline ? `online_${apiKey}_sls` : `offline_${apiKey}_sls`;
    const hash = crypto.createHash('sha256');
    const hashedShop = hash.update(cleanShop + hashkey).digest('hex');
    const state = isOnline ? `online_${hashedShop}` : `offline_${hashedShop}`;

    const query = {
      client_id: config.apiKey,
      scope: config.scopes.toString(),
      redirect_uri: `${config.hostScheme}://${config.hostName}${callbackPath}`,
      state,
      'grant_options[]': isOnline ? 'per-user' : '',
    };
    const processedQuery = new ProcessedQuery();
    processedQuery.putAll(query);

    const redirectUrl = `https://${cleanShop}/admin/oauth/authorize${processedQuery.stringify()}`;
    response.statusCode = 302;
    response.statusText = 'Found';
    response.headers = {
      ...response.headers,
      Location: redirectUrl,
    };

    log.debug(`OAuth started, redirecting to ${redirectUrl}`, {shop, isOnline});

    return abstractConvertResponse(response, adapterArgs);
  };
}

export function callback(config: ConfigInterface) {
  return async function callback<T = AdapterHeaders>({
    ...adapterArgs
  }: CallbackParams): Promise<CallbackResponse<T>> {
    throwIfCustomStoreApp(
      config.isCustomStoreApp,
      'Cannot perform OAuth for private apps',
    );

    const log = logger(config);

    const request = await abstractConvertRequest(adapterArgs);

    const query = new URL(
      request.url,
      `${config.hostScheme}://${config.hostName}`,
    ).searchParams;
    const shop = query.get('shop')!;

    const response = {} as NormalizedResponse;
    if (isbot(request.headers['User-Agent'])) {
      logForBot({request, log, func: 'callback'});
      throw new ShopifyErrors.BotActivityDetected(
        'Invalid OAuth callback initiated by bot',
      );
    }

    log.info('Completing OAuth', {shop});
    const cookies = new Cookies(request, response, {
      keys: [config.apiSecretKey],
      secure: true,
    });
    const cleanShop = sanitizeShop(config)(query.get('shop')!, true)!;

    const isOnline = query.get('state')?.startsWith('online_');
    const apiKey = config.apiKey;
    const hashkey = isOnline ? `online_${apiKey}_sls` : `offline_${apiKey}_sls`;
    const hash = crypto.createHash('sha256');
    const hashedShop = hash.update(cleanShop + hashkey).digest('hex');
    const state = isOnline ? `online_${hashedShop}` : `offline_${hashedShop}`;

    const authQuery: AuthQuery = Object.fromEntries(query.entries());
    if (!(await validQuery({config, query: authQuery, state}))) {
      log.error('Invalid OAuth callback', {shop, state});

      throw new ShopifyErrors.InvalidOAuthError('Invalid OAuth callback.');
    }

    log.debug('OAuth request is valid, requesting access token', {shop});

    const body = {
      client_id: config.apiKey,
      client_secret: config.apiSecretKey,
      code: query.get('code'),
    };

    const postParams = {
      path: '/admin/oauth/access_token',
      type: DataType.JSON,
      data: body,
    };

    const HttpClient = httpClientClass(config);
    const client = new HttpClient({domain: cleanShop});
    const postResponse = await client.post(postParams);

    const session: Session = createSession({
      postResponse,
      shop: cleanShop,
      state,
      config,
    });

    if (!config.isEmbeddedApp) {
      await cookies.setAndSign(SESSION_COOKIE_NAME, session.id, {
        expires: session.expires,
        sameSite: 'lax',
        secure: true,
        path: '/',
      });
    }

    return {
      headers: (await abstractConvertHeaders(
        cookies.response.headers!,
        adapterArgs,
      )) as T,
      session,
    };
  };
}

async function validQuery({
  config,
  query,
  state,
}: {
  config: ConfigInterface;
  query: AuthQuery;
  state: string;
}): Promise<boolean> {
  return (
    (await validateHmac(config)(query)) &&
    safeCompare(query.state!, state)
  );
}

function createSession({
  config,
  postResponse,
  shop,
  state,
}: {
  config: ConfigInterface;
  postResponse: RequestReturn;
  shop: string;
  state: string;
}): Session {
  const associatedUser = (postResponse.body as OnlineAccessResponse)
    .associated_user;
  const isOnline = Boolean(associatedUser);

  logger(config).info('Creating new session', {shop, isOnline});

  if (isOnline) {
    let sessionId: string;
    const responseBody = postResponse.body as OnlineAccessResponse;
    const {access_token, scope, ...rest} = responseBody;
    const sessionExpiration = new Date(
      Date.now() + responseBody.expires_in * 1000,
    );

    if (config.isEmbeddedApp) {
      sessionId = getJwtSessionId(config)(
        shop,
        `${(rest as OnlineAccessInfo).associated_user.id}`,
      );
    } else {
      sessionId = uuidv4();
    }

    return new Session({
      id: sessionId,
      shop,
      state,
      isOnline,
      accessToken: access_token,
      scope,
      expires: sessionExpiration,
      onlineAccessInfo: rest,
    });
  } else {
    const responseBody = postResponse.body as AccessTokenResponse;
    return new Session({
      id: getOfflineId(config)(shop),
      shop,
      state,
      isOnline,
      accessToken: responseBody.access_token,
      scope: responseBody.scope,
    });
  }
}

function throwIfCustomStoreApp(
  isCustomStoreApp: boolean,
  message: string,
): void {
  if (isCustomStoreApp) {
    throw new ShopifyErrors.PrivateAppError(message);
  }
}
