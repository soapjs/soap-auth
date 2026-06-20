# SoapAuth

Authentication strategies, session handling, MFA, and token helpers for the SoapJS ecosystem.

`@soapjs/soap-auth` provides composable authentication primitives for HTTP and socket applications. It includes JWT, local credentials, basic auth, API key auth, built-in OAuth2 social providers, sessions, roles, rate limiting, account lockout, password helpers, MFA/TOTP, PKCE, and JWKS verification.

The package does not depend on Passport or provider SDKs. Built-in and configurable OAuth2 strategies use platform `fetch` plus user-provided mapping callbacks, so applications can start quickly and still replace any part of the auth flow with their own implementation.

## Installation

```sh
npm install @soapjs/soap-auth @soapjs/soap
```

## Requirements

- Node.js 24.17.0 or newer
- `@soapjs/soap` 0.12 or newer

## Quick Start

```ts
import { createJwtAuthConfig, SoapAuth } from "@soapjs/soap-auth";

const auth = await SoapAuth.create({
  http: {
    jwt: createJwtAuthConfig({
      accessSecret: process.env.JWT_ACCESS_SECRET!,
      refreshSecret: process.env.JWT_REFRESH_SECRET!,
      user: {
        fetchUser: async (payload) => users.findById((payload as any).id),
      },
    }),
  },
});

const result = await auth.getHttpStrategy("jwt").authenticate(context);
```

## Recipes

Recipes are framework-neutral config helpers. They return plain SoapAuth config objects and do not import Express, Passport, provider SDKs, or any other adapter library.

```ts
import {
  createApiKeyAuthConfig,
  createHybridOAuth2ProviderConfig,
  createJwtAuthConfig,
  createLocalAuthConfig,
  createOAuth2ProviderConfig,
  oauth2ProviderEndpoints,
} from "@soapjs/soap-auth";
```

Available recipes:

- `createJwtAuthConfig(...)`
- `createLocalAuthConfig(...)`
- `createBasicAuthConfig(...)`
- `createApiKeyAuthConfig(...)`
- `createOAuth2ProviderConfig(...)`
- `createHybridOAuth2ProviderConfig(...)`
- `oauth2ProviderEndpoints.auth0(...)`
- `oauth2ProviderEndpoints.keycloak(...)`
- `oauth2ProviderEndpoints.discord()`
- `oauth2ProviderEndpoints.google()`
- `oauth2ProviderEndpoints.github()`
- `oauth2ProviderEndpoints.facebook()`

Recipes are also available from `@soapjs/soap-auth/recipes`.

## Factory Configuration

`SoapAuth.create()` registers built-in strategies from config:

- `http.jwt` as `jwt`
- `http.local` as `local`
- `http.basic` as `basic`
- `http.apiKey` as `api-key`
- `http.oauth2.google` as `google`
- `http.oauth2.github` as `github`
- `http.oauth2.facebook` as `facebook`
- any other `http.oauth2.<name>` with OAuth2 endpoints as `<name>`
- any `http.hybridOAuth2.<name>` with OAuth2 endpoints as `<name>`
- `socket.jwt` as `jwt`
- `socket.apiKey` as `api-key`

Custom strategies can be registered through `http.custom`, `socket.custom`, or manually with `addStrategy(strategy, name, category)`.

## Local Credentials

```ts
import { createLocalAuthConfig } from "@soapjs/soap-auth";

const auth = await SoapAuth.create({
  http: {
    local: createLocalAuthConfig({
      credentials: {
        extractCredentials: (ctx: any) => ({
          identifier: ctx.body.email,
          password: ctx.body.password,
        }),
        verifyCredentials: async (identifier, password) =>
          users.verifyPassword(identifier, password),
      },
      user: {
        fetchUser: async (identifier) => users.findByEmail(String(identifier)),
      },
      basePath: "/auth",
    }),
  },
});
```

## API Key

```ts
import { createApiKeyAuthConfig } from "@soapjs/soap-auth";

const auth = await SoapAuth.create({
  http: {
    apiKey: createApiKeyAuthConfig({
      keyType: "long-term",
      extractApiKey: (ctx: any) => ctx.headers["x-api-key"] ?? null,
      retrieveUserByApiKey: async (apiKey) => apiKeys.findUser(apiKey),
      isApiKeyExpired: async (apiKey) => apiKeys.isExpired(apiKey),
      trackApiKeyUsage: async (apiKey) => apiKeys.touch(apiKey),
    }),
  },
});
```

## Sessions

```ts
import { MemorySessionStore, SoapAuth } from "@soapjs/soap-auth";

const auth = await SoapAuth.create({
  session: {
    secret: process.env.SESSION_SECRET!,
    store: new MemorySessionStore(),
    getSessionId: (ctx: any) =>
      ctx.cookies?.SESSIONID ?? ctx.headers?.["x-session-id"] ?? null,
  },
  http: {
    local: localConfig,
  },
});
```

`MemorySessionStore` is useful for tests and local development. Production applications should provide a durable `SessionStore` backed by a database, Redis, or another shared storage system.

## OAuth2 Providers

```ts
const auth = await SoapAuth.create({
  http: {
    oauth2: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "https://example.com/auth/google/callback",
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID!,
        clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        redirectUri: "https://example.com/auth/github/callback",
      },
    },
  },
});
```

Providers with standard OAuth2/OIDC endpoints can use configurable OAuth2. Providers with unusual token exchange, user lookup, or redirect requirements can be implemented as a subclass of `OAuth2Strategy` or `HttpOAuth2Strategy` and registered through `http.custom`.

## Configurable OAuth2 Providers

Most OAuth2/OIDC providers do not need a custom class. Provide the endpoints and a profile mapper:

```ts
import { createOAuth2ProviderConfig } from "@soapjs/soap-auth";

const auth = await SoapAuth.create({
  http: {
    oauth2: {
      auth0: createOAuth2ProviderConfig({
        provider: "auth0",
        clientId: process.env.AUTH0_CLIENT_ID!,
        clientSecret: process.env.AUTH0_CLIENT_SECRET!,
        redirectUri: "https://example.com/auth/auth0/callback",
        presetOptions: { domain: "tenant.auth0.com" },
        user: {
          fetchUser: async () => null,
          validateUser: async (profile: any) => ({
            id: profile.sub,
            email: profile.email,
            username: profile.nickname ?? profile.name,
            picture: profile.picture,
          }),
        },
      }),
    },
  },
});
```

For providers without a `userinfo` endpoint, implement `user.fetchUser(accessToken)` and return your application user directly.

## Configurable Hybrid OAuth2

Hybrid OAuth2 tries existing JWT/session auth first, then falls back to OAuth2. This is useful when browser users log in through OAuth2 but API clients can keep using JWT.

```ts
import { createHybridOAuth2ProviderConfig } from "@soapjs/soap-auth";

const auth = await SoapAuth.create({
  session: sessionConfig,
  http: {
    jwt: jwtConfig,
    hybridOAuth2: {
      enterprise: createHybridOAuth2ProviderConfig({
        provider: "enterprise",
        clientId: process.env.IDP_CLIENT_ID!,
        clientSecret: process.env.IDP_CLIENT_SECRET!,
        redirectUri: "https://example.com/auth/enterprise/callback",
        endpoints: {
          authorizationUrl: "https://idp.example.com/authorize",
          tokenUrl: "https://idp.example.com/token",
          userInfoUrl: "https://idp.example.com/userinfo",
        },
        user: {
          fetchUser: async () => null,
          validateUser: async (profile: any) => ({
            id: profile.sub,
            email: profile.email,
          }),
        },
      }),
    },
  },
});
```

## Custom Strategies

When the built-in config is not enough, implement `AuthStrategy` directly:

```ts
const auth = await SoapAuth.create({
  http: {
    custom: {
      internal: {
        async authenticate(ctx: any) {
          const user = await internalAuth.verify(ctx.headers.authorization);
          return user ? { user } : null;
        },
      },
    },
  },
});
```

No external strategy package is required; custom strategies only need an `authenticate(context)` method.

## MFA, Roles, Rate Limits, and Lockout

Shared controls can be attached to credential strategies:

```ts
const localConfig = {
  credentials,
  user,
  routes,
  mfa: {
    isMfaRequired: (user: any) => user.mfaEnabled,
    extractMfaCode: (ctx: any) => ctx.body.mfaCode,
    validateMfaCode: async (user: any, code: string) =>
      mfa.verify(user.id, code),
  },
  role: {
    roles: ["admin"],
    authorizeByRoles: async (user: any, roles: string[]) =>
      roles.includes(user.role),
  },
  rateLimit: {
    checkRateLimit: async (ctx: any) => rateLimiter.isLimited(ctx.ip),
    incrementRequestCount: async (ctx: any) => rateLimiter.increment(ctx.ip),
  },
};
```

## Release Checks

Before publishing:

```sh
npm run test:unit
npm run build
npm pack --dry-run
npm audit --omit=dev
```

The package publishes compiled CommonJS output from `build/` and TypeScript declarations.

## License

MIT
