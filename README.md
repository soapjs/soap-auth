# SoapAuth - Authentication Strategy Manager

## Table of Contents

1. [Introduction](#introduction)
   - [What is `SoapAuth`?](#what-is-soapauth)
   - [Key Features](#key-features)
   - [Supported Authentication Strategies](#supported-authentication-strategies)
   - [When to Use `SoapAuth`](#when-to-use-soapauth)

2. [Installation & Setup](#installation--setup)
   - [Prerequisites](#prerequisites)
   - [Installing `soap-auth`](#installing-soap-auth)
   - [Basic Configuration](#basic-configuration)

3. [Core Concepts](#core-concepts)
   - [Authentication Strategies (`AuthStrategy`)](#authentication-strategies-authstrategy)
   - [`SoapAuth` Core Class Overview](#soapauth-core-class-overview)
   - [How Strategies Work with `SoapAuth`](#how-strategies-work-with-soapauth)
   - [HTTP vs. WebSocket Authentication](#http-vs-websocket-authentication)

4. [Implementing Strategies](#implementing-strategies)

<!-- WIP
5. [Using `SoapAuth` in Different Environments](#using-soapauth-in-different-environments)
   - [Express.js Integration](#expressjs-integration)
     - [Middleware Setup](#middleware-setup)
     - [Protecting Routes](#protecting-routes)
     - [Example: Authenticating Requests in Express](#example-authenticating-requests-in-express)
   - [WebSocket Authentication](#websocket-authentication)
     - [How WebSocket Authentication Works](#how-websocket-authentication-works)
     - [Example: Securing WebSocket Connections](#example-securing-websocket-connections)
   - [GraphQL Authentication](#graphql-authentication)
     - [Using `SoapAuth` with Apollo Server](#using-soapauth-with-apollo-server)
     - [Example: Adding Authentication to GraphQL Resolvers](#example-adding-authentication-to-graphql-resolvers)
   - [Microservices & External APIs](#microservices--external-apis)
     - [Using `SoapAuth` for Microservices](#using-soapauth-for-microservices)
     - [Example: Validating API Requests from External Services](#example-validating-api-requests-from-external-services)

6. [Advanced Usage](#advanced-usage)
   - [Handling Multiple Strategies Simultaneously](#handling-multiple-strategies-simultaneously)
   - [Refreshing Tokens and Session Management](#refreshing-tokens-and-session-management)
   - [Logging and Error Handling](#logging-and-error-handling) -->


## 1️. Introduction

### What is `SoapAuth`?

`SoapAuth` is a **flexible authentication strategy manager** and one of the core modules of `@soapjs` – a toolkit for building clean architecture-based applications efficiently. 

It provides a **structured and extensible approach** to authentication, allowing developers to manage multiple authentication strategies across different environments, including **HTTP APIs (Express.js), WebSockets, GraphQL, and microservices**.


With `SoapAuth`, you can:

- Easily **add, remove, and switch authentication strategies** dynamically.
- Support **OAuth2, JWT, API Keys, and custom authentication strategies**.
- Use it in **Express.js, WebSockets, GraphQL, and microservices**.
- Handle **token refresh, session management, and error handling** efficiently.

### Key Features

✔ **Multi-strategy support** – Use different authentication methods within the same application.  
✔ **Modular and extensible** – Easily add new authentication strategies.  
✔ **Works with HTTP & WebSockets** – Supports both request-based and persistent connection authentication.  
✔ **Easy integration** – Plug it into Express, WebSockets, GraphQL, or any custom API.  
✔ **Dynamic management** – Add, remove, or update authentication strategies at runtime.  
✔ **Built-in logging and debugging** – Helps troubleshoot authentication issues.  

### Supported Authentication Strategies

| Strategy Type      | Description |
|--------------------|------------|
| **OAuth2**        | Authenticate users via external providers like Google, Facebook, or GitHub. |
| **JWT (JSON Web Token)** | Secure API endpoints with token-based authentication. |
| **API Key**       | Use API keys for authentication in RESTful services. |
| **Custom Strategies** | Define your own authentication mechanisms based on your needs. |

### When to Use `SoapAuth`?

Use `SoapAuth` if you need:

- **Multiple authentication methods** in your application (e.g., JWT for API + OAuth2 for users).
- **A structured way** to manage authentication across different request types (HTTP, WebSockets).
- **Flexibility to swap authentication methods** without modifying business logic.
- **Easy expansion** with custom authentication strategies.

## 2️. Installation & Setup

### Prerequisites

Before installing `soap-auth`, ensure you have the following:

- **Node.js** (v16+ recommended)
- **TypeScript** (optional but recommended for type safety)
- **A package manager** (`npm`, `yarn`, or `pnpm`)

### Installing `soap-auth`

You can install `soap-auth` using your preferred package manager:

```sh
# Using npm
npm install @soapjs/soap-auth

# Using yarn
yarn add @soapjs/soap-auth

# Using pnpm
pnpm add @soapjs/soap-auth
```

### Basic Configuration

`soap-auth` serves as the **core authentication manager** within the `@soapjs` ecosystem. It provides a **framework-agnostic foundation** for authentication strategies and is designed to be extended for use in specific frameworks like Express, WebSockets, and others.

To start using `soap-auth`, you need to configure it with authentication strategies.

#### **1️. Import `SoapAuth` and Define Strategies**
Create an `auth.ts` file where you initialize `SoapAuth` with the authentication strategies you plan to use.

```ts
import { SoapAuth } from "@soapjs/soap-auth";
import { OAuth2Strategy, JwtStrategy } from "@soapjs/soap-auth";

const soapAuth = new SoapAuth({
  strategies: {
    http: {
      oauth2: new OAuth2Strategy({
        clientId: "your-client-id",
        clientSecret: "your-client-secret",
        endpoints: {
          authorizationUrl: "https://provider.com/oauth/authorize",
          tokenUrl: "https://provider.com/oauth/token",
          userInfoUrl: "https://provider.com/userinfo",
        },
      }),
      jwt: new JwtStrategy({
        accessToken: {
          issuer: {
            secretKey: "your-jwt-secret",
            options: {
              issuer: "your-app",
            }
          }
        }
        routes: {
          login: { path: "your-login-path" method: "POST" },
          logout: { path: "your-logout-path" method: "POST" },
          ...
        },
      }),
    },
  },
  logger: console, // Optional logging
});

export default soapAuth;
```

#### **2️. Initialize Strategies**
Before using authentication, ensure all strategies are properly initialized.

```ts
await soapAuth.init();
```

#### **3️. Authenticating Requests**
To authenticate a request using a specific strategy:

```ts
const authResult = await soapAuth.authenticate("http", "jwt", request);
console.log(authResult.user);
```

### Framework-Specific Implementations

`soap-auth` serves as the **foundation** for authentication in multiple environments. Specific implementations for frameworks like **Express.js, WebSockets, and GraphQL** are built on top of it.

If you're using a specific framework, consider installing its dedicated package:

```sh
# Express.js soap package (WIP)
npm install @soapjs/soap-express

```

These packages extend `soap-auth`, providing **plug-and-play middleware** for authentication in framework-specific contexts.

## 3️. Core Concepts

### Authentication Strategies (`AuthStrategy`)

At the core of `soap-auth` is the concept of **authentication strategies**, which define how authentication should be performed. Each strategy is responsible for:

- Extracting credentials or tokens from the request.
- Validating the provided credentials.
- Returning an authenticated user or rejecting the request.

Examples of authentication strategies include **OAuth2, JWT, API Keys, and custom strategies**.

### `SoapAuth` Core Class Overview

The `SoapAuth` class serves as the **authentication manager**, handling multiple authentication strategies within an application. It allows developers to:

- **Register authentication strategies** dynamically.
- **Manage authentication across different layers** (HTTP, WebSockets, GraphQL, etc.).
- **Authenticate requests** using specific strategies.
- **Handle token storage, session management, and error handling**.

### How Strategies Work with `SoapAuth`

1. **A user sends a request** (e.g., HTTP request, WebSocket connection).
2. **`SoapAuth` selects the appropriate strategy** based on the request context.
3. **The selected strategy authenticates the request** by validating tokens, credentials, or API keys.
4. **If authentication succeeds, the user is granted access**; otherwise, an error is returned.

### HTTP vs. WebSocket Authentication

| Feature | HTTP Authentication | WebSocket Authentication |
|---------|----------------------|--------------------------|
| Request Type | One-time requests | Persistent connection |
| Example Strategies | OAuth2, JWT, API Key | Token-based, session-based |
| Validation | Per request | On connection + periodic checks |

- **For HTTP**, authentication is performed **on each request**.
- **For WebSockets**, authentication happens **once on connection** and may include **token refresh checks** during the session.

Understanding these differences helps in choosing the right strategy for your use case.

## 4️. Implementing Strategies

### Built-in Authentication Strategies

`soap-auth` provides built-in support for multiple authentication strategies:

1. **Basic Authentication** - Username & password via HTTP headers.
2. **Local Authentication** - Custom credential-based authentication.
3. **API Key Authentication** - Secure access using an API key.
4. **JWT Authentication** - Token-based authentication using JSON Web Tokens.
5. **OAuth2 Authentication** - Third-party authentication with OAuth2 providers.

Each strategy is **configurable** and can be **easily extended** or **customized**.

### **Basic Authentication (Username & Password)**
Basic authentication works by extracting credentials from an `Authorization` header.

```ts
import { BasicStrategy } from "@soapjs/soap-auth/strategies/basic.strategy";

const basicAuth = new BasicStrategy({
  credentials: {
    extractCredentials: (context) => {
      const authHeader = context.headers?.authorization;
      if (!authHeader || !authHeader.startsWith("Basic ")) return null;
      const decoded = Buffer.from(authHeader.substring(6), "base64").toString();
      const [username, password] = decoded.split(":");
      return { identifier: username, password };
    },
    verifyCredentials: async (username, password) => {
      const user = await database.getUser(username);
      return user && user.password === password;
    },
  },
  user: {
    getUserData: async (identifier) => database.getUser(identifier),
  },
});
```

#### **Authenticating a Request**
```ts
const authResult = await basicAuth.authenticate(request);
console.log(authResult.user);
```

### **Local Authentication (Custom Credential System)**
Local authentication allows custom username/password authentication.

```ts
import { LocalStrategy } from "@soapjs/soap-auth/strategies/local.strategy";

const localAuth = new LocalStrategy({
  credentials: {
    extractCredentials: (context) => ({
      identifier: context.body.username,
      password: context.body.password,
    }),
    verifyCredentials: async (username, password) => {
      const user = await database.getUser(username);
      return user && user.password === password;
    },
  },
  user: {
    getUserData: async (identifier) => database.getUser(identifier),
  },
});
```

#### **Authenticating a Request**
```ts
const authResult = await localAuth.authenticate(request);
console.log(authResult.user);
```

### **API Key Authentication**
API Key authentication extracts and verifies API keys sent in headers.

```ts
import { ApiKeyStrategy } from "@soapjs/soap-auth/strategies/api-key.strategy";

const apiKeyAuth = new ApiKeyStrategy({
  extractApiKey: (context) => context.headers["x-api-key"],
  retrieveUserByApiKey: async (apiKey) => database.getUserByApiKey(apiKey),
  authorize: async (user, action) => user.permissions.includes(action),
  isApiKeyExpired: async (apiKey) => false,
});
```

#### **Authenticating a Request**
```ts
const authResult = await apiKeyAuth.authenticate(request);
console.log(authResult.user);
```

### **JWT Authentication**
JWT authentication verifies JSON Web Tokens (JWTs) passed in headers.

```ts
import { JwtStrategy } from "@soapjs/soap-auth/strategies/jwt.strategy";

const jwtAuth = new JwtStrategy({
  accessToken: {
    issuer: {
      secretKey: "your-secret-key",
      options: { expiresIn: "1h" },
    },
    retrieve: (context) => context.headers.authorization?.split(" ")[1],
  },
  user: {
    getUserData: async (decodedToken) => database.getUser(decodedToken.sub),
  },
});
```

#### **Authenticating a Request**
```ts
const authResult = await jwtAuth.authenticate(request);
console.log(authResult.user);
```

### **OAuth2 Authentication**
OAuth2 authentication enables integration with third-party providers.

```ts
import { OAuth2Strategy } from "@soapjs/soap-auth/strategies/oauth2.strategy";

const oauth2Auth = new OAuth2Strategy({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://provider.com/oauth/authorize",
    tokenUrl: "https://provider.com/oauth/token",
    userInfoUrl: "https://provider.com/userinfo",
  },
  user: {
    validateUser: async (userData) => database.getUser(userData.email),
  },
});
```

#### **Authenticating a Request**
```ts
const authResult = await oauth2Auth.authenticate(request);
console.log(authResult.user);
```

### **Custom Authentication Strategy**
If you need a custom authentication method, you can extend `AuthStrategy`.

```ts
import { AuthStrategy } from "@soapjs/soap-auth";

class CustomAuthStrategy extends AuthStrategy {
  async authenticate(context) {
    const user = await database.findUser(context.credentials);
    return user ? { user } : null;
  }
}
```

### **Using other auth libraries with `soap-auth`**
Instead of implementing authentication manually, you can integrate `passport.js`.

```ts
import passport from "passport";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { AuthStrategy } from "@soapjs/soap-auth";

class PassportAuthStrategy extends AuthStrategy {

  init() {
    passport.use(
      new FacebookStrategy(
        {
          clientID: "your-facebook-client-id",
          clientSecret: "your-facebook-client-secret",
          callbackURL: "/auth/facebook/callback",
          profileFields: ["id", "emails", "displayName"],
        },
        async (accessToken, refreshToken, profile, done) => {
          const user = await database.findOrCreateUser(profile);
          return done(null, user);
        }
      )
    );
  }
  async authenticate(context) {
    return new Promise((resolve, reject) => {
      passport.authenticate("facebook", (error, user) => {
        if (error || !user) return reject(new Error("Authentication failed"));
        resolve({ user });
      })(context.request, context.response);
    });
  }
}
```
























---

## Installation

```sh
npm install @soapjs/soap-auth
```

---

## Features

- Multiple authentication strategies (local, OAuth2, JWT, API key, basic auth)
- Custom authentication strategy support
- Built-in session management with pluggable session stores
- Token handling for JWT authentication
- Extensible architecture with abstract base classes
- Compatible with framework adapters for seamless integration

---

## Core Classes Overview

### 1. `SoapAuth`
This is the main entry point for managing authentication. It initializes different strategies based on the provided configuration and provides methods for authentication, authorization, and session management.

### 2. `AuthStrategy`
The base interface that all strategies must implement. Provides methods such as `authenticate`, `authorize`, `init`, and `logout`.

### 3. `SessionHandler`
Handles session operations like retrieving, storing, and generating session IDs. It supports multiple session storage mechanisms such as in-memory and file-based stores.

### 4. `TokenAuthStrategy`
Abstract class for token-based authentication strategies, providing methods for handling access and refresh tokens.

### 5. `OAuth2Strategy`
Abstract class for token-based authentication strategies, providing methods for handling access and refresh tokens.

### 6. `CredentialAuthStrategy`
Abstract class for username-password-based authentication strategies.

### 7. `HttpAuthStrategyFactory` & `SocketAuthStrategyFactory`
Factories responsible for creating instances of HTTP and socket-based authentication strategies respectively.

---

## Available Authentication Strategies

### 1. Local Strategy

**When to use:**
- Ideal for applications that require username and password authentication stored locally.

**Configuration example:**
```typescript
const authConfig = {
  http: {
    local: {
      usernameField: "email",
      passwordField: "password",
      validateUser: async (username, password) => {
        return username === "user@example.com" && password === "securepass" ? { id: 1, name: "John Doe" } : null;
      },
    },
  },
};
```

### 2. OAuth2 Strategy

**When to use:**
- Suitable for social logins (Google, Facebook, Twitter, etc.).

**Configuration example:**
```typescript
const authConfig = {
  http: {
    oauth2: {
      google: {
        clientId: "your-client-id",
        clientSecret: "your-client-secret",
        redirectUri: "https://yourapp.com/auth/callback",
        scope: "openid profile email",
        endpoints: {
          authorizationUrl: "https://accounts.google.com/o/oauth2/auth",
          tokenUrl: "https://oauth2.googleapis.com/token",
        },
      },
    },
  },
};
```

### 3. JWT Strategy

**When to use:**
- Suitable for stateless authentication where tokens are passed between the client and server.

**Configuration example:**
```typescript
const authConfig = {
  http: {
    jwt: {
      access: {
        secretKey: "your-secret-key",
        expiresIn: "1h",
        signOptions: { algorithm: "HS256" },
      },
    },
  },
};
```

### 4. API Key Strategy

**When to use:**
- Best for authenticating external services using static API keys.

**Configuration example:**
```typescript
const authConfig = {
  http: {
    apiKey: {
      extractApiKey: (context) => context.headers["x-api-key"],
      retrieveUserByApiKey: async (apiKey) => {
        return apiKey === "valid-api-key" ? { id: 1, role: "admin" } : null;
      },
    },
  },
};
```

### 5. Basic Authentication

**When to use:**
- Useful for simple username-password authentication with minimal overhead.

**Configuration example:**
```typescript
const authConfig = {
  http: {
    basic: {
      validateUser: async (username, password) => {
        return username === "admin" && password === "password" ? { id: 1, role: "admin" } : null;
      },
    },
  },
};
```

---

## Using SoapAuth

```typescript
import { SoapAuth } from "@soapjs/soap-auth";

const auth = new SoapAuth(authConfig);
await auth.init();

const user = await auth.authenticate("local", { email: "user@example.com", password: "securepass" });
console.log("Authenticated user:", user);
```

---

## Creating a Custom Authentication Strategy

To create a custom strategy, extend the appropriate base class depending on the authentication type:

1. **For token-based strategies:** Extend `TokenAuthStrategy`.
2. **For credential-based strategies:** Extend `CredentialAuthStrategy`.
3. **For generic implementations:** Extend `BaseAuthStrategy` directly.

**Example:**
```typescript
class CustomAuthStrategy extends TokenAuthStrategy {
  async authenticate(context) {
    const token = context.headers.authorization;
    if (token === "valid-token") {
      return { user: { id: 1, role: "admin" }, tokens: { accessToken: token } };
    }
    throw new Error("Invalid token");
  }
}
```

---

## Session Management

SoapAuth supports session management through the `SessionHandler` class. The session can be stored using memory, files, or external databases via adapters.

**Example Session Configuration:**
```typescript
const authConfig = {
  session: {
    secret: "your-session-secret",
    sessionKey: "my-session-id",
    store: new MemorySessionStore(),
  },
};
```

---

## Framework Integration

SoapAuth is designed to work with various frameworks such as Express, Koa, Fastify, and more through dedicated adapters.

```typescript
// basic example
app.use(async (req, res, next) => {
  try {
    const user = await auth.authenticate("jwt", req);
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send("Unauthorized");
  }
});
```
## Issues
If you encounter any issues, please feel free to report them [here](https://github.com/soapjs/soap/issues/new/choose).

## Contact
For any questions, collaboration interests, or support needs, you can contact us through the following:

- Official:
  - Website: http://docs.soapjs.com
- Radoslaw Kamysz:
  - Email: [radoslaw.kamysz@gmail.com](mailto:radoslaw.kamysz@gmail.com)
  - Warpcast: [@k4mr4ad](https://warpcast.com/k4mr4ad)
  - Twitter: [@radoslawkamysz](https://x.com/radoslawkamysz)
## License
SoapJS is licensed under the MIT License.