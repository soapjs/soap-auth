# SoapAuth (WIP)

SoapAuth is a comprehensive authentication module based on __Passport.js__, designed to handle various authentication strategies, session management, login, and logout functionalities. This package includes implementations for multiple strategies such as local authentication, OAuth, OAuth2, API key, Bearer, Basic, and Web3 (WiP). It provides a flexible configuration and class-based approach for integrating authentication into your project.

## Features

- **Multiple Authentication Strategies**: Includes implementations for Local, OAuth, OAuth2, API key, Bearer, Basic, and Web3 (Work in Progress).
- **Session Management**: Supports session-based authentication.
- **JWT Support**: Can use JSON Web Tokens (JWT) for stateless authentication.
- **Configurable Routes**: Automatically sets up routes for login, logout, and token refresh.
- **Dynamic Loading**: Only loads necessary dependencies based on the configuration.

## Installation

This package requires the installation of specific dependencies based on the strategies you plan to use. Add the necessary dependencies to your project's `package.json`.

## Dependencies

- **Passport**: Core authentication middleware.
- **Passport Strategies**: Depending on the strategies you need (e.g., `passport-local`, `passport-google-oauth20`, `passport-facebook`, etc.).
- **Web3 (WiP)**: For blockchain-based authentication (e.g., MetaMask).

### Example `package.json` Dependencies

```json
{
  "dependencies": {
    "passport": "^0.4.1",
    "jsonwebtoken": "^8.5.1",
    "express-session": "^1.17.1"
  },
  "optionalDependencies": {
    "passport-google-oauth20": "^2.0.0",
    "passport-facebook": "^3.0.0",
    "passport-local": "^1.0.0",
    "passport-http-bearer": "^1.0.1",
    "passport-http": "^0.3.0",
    "web3": "^1.3.0"
  }
}
```

## Strategies

### Local Strategy

- **Description**: Uses a form with username and password for authentication.
- **Use Case**: Typical web applications.
- **Session**: Yes.
- **JWT**: Optionally.
- **Routes**: `login`, `logout`.

### Basic Strategy

- **Description**: Uses the `Authorization` header with Base64-encoded username and password.
- **Use Case**: APIs where the client is a program.
- **Session**: Optionally.
- **JWT**: No.
- **Routes**: None needed.

### Bearer Strategy

- **Description**: Uses the `Authorization` header with a token (e.g., JWT).
- **Use Case**: Stateless API authentication.
- **Session**: No.
- **JWT**: Yes.
- **Routes**: `login`, `logout`, `refresh-token`.

### OAuth Strategy

- **Description**: Uses OAuth for authentication with external providers (e.g., Google, Facebook).
- **Use Case**: Allowing users to log in with their social media accounts.
- **Session**: Optionally.
- **JWT**: Optionally.
- **Routes**: `login`, `logout`, `callback`, `refresh-token`.

### OAuth2 Strategy

- **Description**: General OAuth2 strategy for any OAuth2 provider.
- **Use Case**: Integrating with OAuth2 providers not covered by specific strategies.
- **Session**: Optionally.
- **JWT**: Optionally.
- **Routes**: `login`, `logout`, `callback`, `refresh-token`.

### API Key Strategy

- **Description**: Uses API keys passed in headers, query parameters, or request body.
- **Use Case**: APIs requiring API key-based authentication.
- **Session**: No.
- **JWT**: No.
- **Routes**: None needed.

### Web3 Strategy

- **Description**: Uses Web3 for authentication, typically involving signing messages with a wallet (e.g., MetaMask).
- **Use Case**: Decentralized applications (dApps), blockchain integration.
- **Session**: Optionally.
- **JWT**: Optionally.
- **Routes**: `login`, `logout`.

## Configuration Example

Here's an example configuration for the authentication module:

```typescript
import { AuthModuleConfig } from './types';

/**
 * Example configuration for the authentication module
 */
const config: AuthModuleConfig = {
  jwt: {
    secretOrKey: process.env.JWT_SECRET!,
    expiresIn: '1h',
    refreshSecretOrKey: process.env.JWT_REFRESH_SECRET!,
    refreshExpiresIn: '7d',
    validate: async (payload) => {
      return true;
    },
    storageMethod: 'cookie',
    cookieOptions: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000,
    },
  },
  session: {
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    serializeUser: (user, done) => {
      done(null, user.id);
    },
    deserializeUser: (id, done) => {
      done(null, { id });
    },
  },
  strategies: {
    local: {
      verify: async (username, password) => {
        return { id: 1, username };
      },
      session: true,
    },
    oauth: {
      google: {
        clientID: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        callbackURL: 'http://localhost:3000/auth/google/callback',
        scope: ['profile', 'email'],
        useOwnJWT: true,
        verify: async (accessToken, refreshToken, profile) => {
          return { id: profile.id, email: profile.emails[0].value };
        },
        session: true,
      },
      facebook: {
        clientID: process.env.FACEBOOK_CLIENT_ID!,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET!,
        callbackURL: 'http://localhost:3000/auth/facebook/callback',
        scope: ['email'],
        useOwnJWT: false,
        verify: async (accessToken, refreshToken, profile) => {
          return { id: profile.id, email: profile.emails[0].value };
        },
        session: true,
      },
    },
    oauth2: {
      genericProvider: {
        authorizationURL: 'https://example.com/oauth/authorize',
        tokenURL: 'https://example.com/oauth/token',
        clientID: 'YOUR_CLIENT_ID',
        clientSecret: 'YOUR_CLIENT_SECRET',
        callbackURL: 'http://localhost:3000/auth/genericProvider/callback',
        scope: ['profile', 'email'],
        useOwnJWT: true,
        verify: async (accessToken, refreshToken, profile) => {
          return { id: profile.id, email: profile.emails[0].value };
        },
        session: true,
      },
    },
    apiKey: {
      headerName: 'x-api-key',
      queryParamName: 'api_key',
      bodyParamName: 'apiKey',
      validate: async (apiKey) => {
        return apiKey === 'my-secure-api-key';
      },
      session: false,
    },
    bearer: {
      verify: (token, done) => {
        done(null, { id: 1, username: 'bearer_user' });
      },
      session: false,
    },
    basic: {
      verify: (username, password, done) => {
        done(null, { id: 1, username });
      },
      session: false,
    },
    web3: {
      verify: (address, signature, done) => {
        done(null, { id: 1, address });
      },
      session: true,
    },
  },
};

export default config;
```

## Usage Example

Here's an example of how to use the SoapAuth module in your project:

```typescript
import { Container } from 'inversify';
import * as SoapExpress from '@soapjs/soap-express';
import * as SoapAuth from '@soapjs/soap-auth';
import config from './config';

export const bootstrap = async () => {
  const container = new Container();
  const dependencies = new MyDependencies(container);
  const router = new MyRouter(container);
  const soapAuth = new SoapAuth({
    jwt: config.jwt,
    session: config.session,
    strategies: config.strategies,
  });

  const { httpServer } = await SoapExpress.bootstrap(
    config.api,
    dependencies,
    router,
    {
      auth: soapAuth,
      logger: winston.createLogger(config.logger),
      errorHandler,
      httpErrorHandler,
    }
  );
};

bootstrap();
```

## Notes

This package is designed to be used with HTTP but will be extended in the future. It provides a robust and flexible authentication solution for modern web applications and APIs.

## Issues
If you encounter any issues, please feel free to report them [here](https://github.com/soapjs/soap/issues/new/choose).

## Contact
For any questions, collaboration interests, or support needs, you can contact us through the following:

- Official:
  - Email: [contact@soapjs.com](mailto:contact@soapjs.com)
  - Website: https://docs.soapjs.com
- Radoslaw Kamysz:
  - Email: [radoslaw.kamysz@gmail.com](mailto:radoslaw.kamysz@gmail.com)
  - Warpcast: [@k4mr4ad](https://warpcast.com/k4mr4ad)
  - Twitter: [@radoslawkamysz](https://x.com/radoslawkamysz)
## License
SoapAuth is licensed under the MIT License.
