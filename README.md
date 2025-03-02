# SoapAuth - Modular Authentication Solution

SoapAuth is a flexible library for handling authentication and identity management. It allows you to easily implement various authentication strategies such as JWT, OAuth2, Basic Auth, Local Auth, API Key, and more. As part of the **@soapjs** ecosystem, it can be easily extended with additional components like **soap**, **soap-express**, and **soap-cli**.

## Installation
```sh
npm install @soapjs/soap-auth
```

## Key Features
- **Supports multiple authentication strategies** (JWT, OAuth2, API Key, Basic, Local, Hybrid OAuth2).
- **Works with both HTTP and WebSocket protocols.**
- **Manages sessions, MFA, roles, account locks, and rate limiting.**
- **Easy configuration and extendability.**
- **Integration with frameworks like Express, NestJS, etc.**

---

## Basic Usage
```typescript
import { SoapAuth, JwtStrategy } from "@soapjs/soap-auth";

const auth = new SoapAuth();
auth.addStrategy(new JwtStrategy({ secret: "super-secret-key" }), "jwt", "http");
// ...
const result = await auth.getHttpStrategy<JwtStrategy>("jwt").authenticate(request);
console.log(result.user);
```

---

## Supported Authentication Strategies

SoapAuth supports multiple authentication strategies. Below is a description and example configuration for each.

### **JWT Strategy** *(Token-based authentication)*
```typescript
import { JwtStrategy } from "@soapjs/soap-auth";

auth.addStrategy(new JwtStrategy({
  secret: "your-secret-key",
  accessToken: {
    expiresIn: "1h",
  },
  refreshToken: {
    expiresIn: "7d",
  },
}), "jwt", "http");
```

### **OAuth2 Strategy** *(OAuth 2.0 authentication)*
```typescript
import { OAuth2Strategy } from "@soapjs/soap-auth";

auth.addStrategy(new OAuth2Strategy({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  endpoints: {
    authorizationUrl: "https://auth.server.com/auth",
    tokenUrl: "https://auth.server.com/token",
  },
}), "oauth2", "http");
```

### **API Key Strategy** *(Key-based authentication)*
```typescript
import { ApiKeyStrategy } from "@soapjs/soap-auth";

auth.addStrategy(new ApiKeyStrategy({
  extractApiKey: (ctx) => ctx.headers["x-api-key"],
  retrieveUserByApiKey: async (key) => {
    return mockDatabase.findUserByApiKey(key);
  },
}), "apikey", "http");
```

### **Basic Auth Strategy** *(Username & Password authentication)*
```typescript
import { BasicStrategy } from "@soapjs/soap-auth";

auth.addStrategy(new BasicStrategy({
  extractCredentials: (ctx) => {
    return { identifier: ctx.body.username, password: ctx.body.password };
  },
  verifyCredentials: async (id, pass) => {
    return mockDatabase.verifyUser(id, pass);
  },
}), "basic", "http");
```

### **Local Strategy** *(Custom authentication logic)*
```typescript
import { LocalStrategy } from "@soapjs/soap-auth";

auth.addStrategy(new LocalStrategy({
  extractCredentials: (ctx) => ({ identifier: ctx.query.email, password: ctx.query.pass }),
  verifyCredentials: async (id, pass) => {
    return mockDatabase.verifyUser(id, pass);
  },
}), "local", "http");
```

### **Hybrid OAuth2 Strategy** *(Combination of multiple authentication methods)*
```typescript
import { HybridOAuth2Strategy } from "@soapjs/soap-auth";

auth.addStrategy(new HybridOAuth2Strategy({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  oauth2: {
    endpoints: {
      authorizationUrl: "https://oauth.provider.com/auth",
      tokenUrl: "https://oauth.provider.com/token",
    },
  },
}), "hybrid-oauth2", "http");
```

---

## Configuration & Extensions
### Role Management
```typescript
role: {
  authorizeByRoles: async (user, roles) => roles.includes(user.role),
  roles: ["admin", "user"]
}
```
### Multi-Factor Authentication (MFA)
```typescript
mfa: {
  isMfaRequired: (user) => user.requiresMfa,
  validateMfaCode: async (user, code) => mockDatabase.checkMfaCode(user, code),
}
```
### Account Locking after Failed Logins
```typescript
lock: {
  isAccountLocked: async (account) => mockDatabase.isLocked(account),
  lockAccount: async (account) => mockDatabase.lock(account),
}
```
### Rate Limiting
```typescript
rateLimit: {
  checkRateLimit: async (ctx) => false, // No limits
}
```

---

## FAQ
**How to report an issue?**  
Open an issue on GitHub.  

**How to extend `soap-auth` with custom strategies?**  
You can create your own class extending `BaseAuthStrategy` and implementing `authenticate()`.  

---
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
SoapAuth is licensed under the MIT License.
