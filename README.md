# SoapAuth

**SoapAuth** is a flexible authentication and authorization module designed to provide support for various authentication strategies. It is intended to be used alongside a specific framework adapter, serving as the core authentication engine.

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

### 4. `TokenBasedAuthStrategy`
Abstract class for token-based authentication strategies, providing methods for handling access and refresh tokens.

### 5. `CredentialBasedAuthStrategy`
Abstract class for username-password-based authentication strategies.

### 6. `HttpAuthStrategyFactory` & `SocketAuthStrategyFactory`
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

1. **For token-based strategies:** Extend `TokenBasedAuthStrategy`.
2. **For credential-based strategies:** Extend `CredentialBasedAuthStrategy`.
3. **For generic implementations:** Extend `BaseAuthStrategy` directly.

**Example:**
```typescript
class CustomAuthStrategy extends TokenBasedAuthStrategy {
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
