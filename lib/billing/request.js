"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.request = void 0;
const tslib_1 = require("tslib");
const types_1 = require("../types");
const error_1 = require("../error");
const get_embedded_app_url_1 = require("../auth/get-embedded-app-url");
const graphql_client_1 = require("../clients/graphql/graphql_client");
const crypto_1 = require("../../runtime/crypto");
const types_2 = require("../../runtime/crypto/types");
function request(config) {
    return function ({ session, plan, isTest = true, returnUrl: returnUrlParam, }) {
        var _a;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!config.billing || !config.billing[plan]) {
                throw new error_1.BillingError({
                    message: `Could not find plan ${plan} in billing settings`,
                    errorData: [],
                });
            }
            const billingConfig = config.billing[plan];
            const cleanShopName = session.shop.replace('.myshopify.com', '');
            const embeddedAppUrl = (0, get_embedded_app_url_1.buildEmbeddedAppUrl)(config)((0, crypto_1.hashString)(`admin.shopify.com/store/${cleanShopName}`, types_2.HashFormat.Base64));
            const appUrl = `${config.hostScheme}://${config.hostName}`;
            // if provided a return URL, use it, otherwise use the embedded app URL or hosted app URL
            const returnUrl = returnUrlParam || (config.isEmbeddedApp ? embeddedAppUrl : appUrl);
            const GraphqlClient = (0, graphql_client_1.graphqlClientClass)({ config });
            const client = new GraphqlClient({ session });
            let data;
            switch (billingConfig.interval) {
                case types_1.BillingInterval.OneTime: {
                    const mutationOneTimeResponse = yield requestSinglePayment({
                        billingConfig: billingConfig,
                        plan,
                        client,
                        returnUrl,
                        isTest,
                    });
                    data = mutationOneTimeResponse.data.appPurchaseOneTimeCreate;
                    break;
                }
                case types_1.BillingInterval.Usage: {
                    const mutationUsageResponse = yield requestUsagePayment({
                        billingConfig: billingConfig,
                        plan,
                        client,
                        returnUrl,
                        isTest,
                    });
                    data = mutationUsageResponse.data.appSubscriptionCreate;
                    break;
                }
                default: {
                    const mutationRecurringResponse = yield requestRecurringPayment({
                        billingConfig: billingConfig,
                        plan,
                        client,
                        returnUrl,
                        isTest,
                    });
                    data = mutationRecurringResponse.data.appSubscriptionCreate;
                }
            }
            if ((_a = data.userErrors) === null || _a === void 0 ? void 0 : _a.length) {
                throw new error_1.BillingError({
                    message: 'Error while billing the store',
                    errorData: data.userErrors,
                });
            }
            return data.confirmationUrl;
        });
    };
}
exports.request = request;
function requestRecurringPayment({ billingConfig, plan, client, returnUrl, isTest, }) {
    var _a, _b, _c, _d, _e, _f;
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const mutationResponse = yield client.query({
            data: {
                query: RECURRING_PURCHASE_MUTATION,
                variables: {
                    name: plan,
                    trialDays: billingConfig.trialDays,
                    replacementBehavior: billingConfig.replacementBehavior,
                    returnUrl,
                    test: isTest,
                    lineItems: [
                        {
                            plan: {
                                appRecurringPricingDetails: {
                                    interval: billingConfig.interval,
                                    price: {
                                        amount: billingConfig.amount,
                                        currencyCode: billingConfig.currencyCode,
                                    },
                                    discount: {
                                        durationLimitInIntervals: (_a = billingConfig.discount) === null || _a === void 0 ? void 0 : _a.durationLimitInIntervals,
                                        value: {
                                            amount: (_c = (_b = billingConfig.discount) === null || _b === void 0 ? void 0 : _b.value) === null || _c === void 0 ? void 0 : _c.amount,
                                            percentage: (_e = (_d = billingConfig.discount) === null || _d === void 0 ? void 0 : _d.value) === null || _e === void 0 ? void 0 : _e.percentage,
                                        },
                                    },
                                },
                            },
                        },
                    ],
                },
            },
        });
        if ((_f = mutationResponse.body.errors) === null || _f === void 0 ? void 0 : _f.length) {
            throw new error_1.BillingError({
                message: 'Error while billing the store',
                errorData: mutationResponse.body.errors,
            });
        }
        return mutationResponse.body;
    });
}
function requestUsagePayment({ billingConfig, plan, client, returnUrl, isTest, }) {
    var _a;
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const mutationResponse = yield client.query({
            data: {
                query: RECURRING_PURCHASE_MUTATION,
                variables: {
                    name: plan,
                    returnUrl,
                    test: isTest,
                    trialDays: billingConfig.trialDays,
                    replacementBehavior: billingConfig.replacementBehavior,
                    lineItems: [
                        {
                            plan: {
                                appUsagePricingDetails: {
                                    terms: billingConfig.usageTerms,
                                    cappedAmount: {
                                        amount: billingConfig.amount,
                                        currencyCode: billingConfig.currencyCode,
                                    },
                                },
                            },
                        },
                    ],
                },
            },
        });
        if ((_a = mutationResponse.body.errors) === null || _a === void 0 ? void 0 : _a.length) {
            throw new error_1.BillingError({
                message: `Error while billing the store:: ${mutationResponse.body.errors}`,
                errorData: mutationResponse.body.errors,
            });
        }
        return mutationResponse.body;
    });
}
function requestSinglePayment({ billingConfig, plan, client, returnUrl, isTest, }) {
    var _a;
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const mutationResponse = yield client.query({
            data: {
                query: ONE_TIME_PURCHASE_MUTATION,
                variables: {
                    name: plan,
                    returnUrl,
                    test: isTest,
                    price: {
                        amount: billingConfig.amount,
                        currencyCode: billingConfig.currencyCode,
                    },
                },
            },
        });
        if ((_a = mutationResponse.body.errors) === null || _a === void 0 ? void 0 : _a.length) {
            throw new error_1.BillingError({
                message: 'Error while billing the store',
                errorData: mutationResponse.body.errors,
            });
        }
        return mutationResponse.body;
    });
}
const RECURRING_PURCHASE_MUTATION = `
  mutation test(
    $name: String!
    $lineItems: [AppSubscriptionLineItemInput!]!
    $returnUrl: URL!
    $test: Boolean
    $trialDays: Int
    $replacementBehavior: AppSubscriptionReplacementBehavior
  ) {
    appSubscriptionCreate(
      name: $name
      lineItems: $lineItems
      returnUrl: $returnUrl
      test: $test
      trialDays: $trialDays
      replacementBehavior: $replacementBehavior
    ) {
      confirmationUrl
      userErrors {
        field
        message
      }
    }
  }
`;
const ONE_TIME_PURCHASE_MUTATION = `
  mutation test(
    $name: String!
    $price: MoneyInput!
    $returnUrl: URL!
    $test: Boolean
  ) {
    appPurchaseOneTimeCreate(
      name: $name
      price: $price
      returnUrl: $returnUrl
      test: $test
    ) {
      confirmationUrl
      userErrors {
        field
        message
      }
    }
  }
`;
//# sourceMappingURL=request.js.map