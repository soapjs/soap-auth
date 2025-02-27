# OAuth2 Examples (WIP)**

## **1. Google OAuth2 Example**

```typescript
const googleAuthConfig: OAuth2AuthStrategyConfig = {
  clientId: "your-google-client-id",
  clientSecret: "your-google-client-secret",
  redirectUri: "https://yourapp.com/auth/google/callback",
  scope: "openid profile email",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://accounts.google.com/o/oauth2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  validateUser: async (tokenPayload) => {
    return {
      id: tokenPayload.sub,
      email: tokenPayload.email,
      name: tokenPayload.name,
      picture: tokenPayload.picture,
    };
  },
};
```

**Usage:**

```typescript
class GoogleAuthStrategy extends OAuth2AuthStrategy<Express.Request, any> {
  protected async fetchUser(decodedToken: any): Promise<any | null> {
    return decodedToken ? { id: decodedToken.sub, email: decodedToken.email } : null;
  }
}

const googleStrategy = new GoogleAuthStrategy(googleAuthConfig, accessTokenHandler, refreshTokenHandler);
```

---

## **2. Facebook OAuth2 Example**

```typescript
const facebookAuthConfig: OAuth2AuthStrategyConfig = {
  clientId: "your-facebook-client-id",
  clientSecret: "your-facebook-client-secret",
  redirectUri: "https://yourapp.com/auth/facebook/callback",
  scope: "email public_profile",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://www.facebook.com/v12.0/dialog/oauth",
    tokenUrl: "https://graph.facebook.com/v12.0/oauth/access_token",
    userInfoUrl: "https://graph.facebook.com/me?fields=id,name,email,picture",
  },
  validateUser: async (tokenPayload) => {
    return {
      id: tokenPayload.id,
      email: tokenPayload.email,
      name: tokenPayload.name,
      picture: tokenPayload.picture.data.url,
    };
  },
};
```

**Usage:**

```typescript
class FacebookAuthStrategy extends OAuth2AuthStrategy<Express.Request, any> {
  protected async fetchUser(decodedToken: any): Promise<any | null> {
    return decodedToken ? { id: decodedToken.id, email: decodedToken.email } : null;
  }
}

const facebookStrategy = new FacebookAuthStrategy(facebookAuthConfig, accessTokenHandler, refreshTokenHandler);
```

---

## **3. Twitter (X) OAuth2 Example**

```typescript
const twitterAuthConfig: OAuth2AuthStrategyConfig = {
  clientId: "your-twitter-client-id",
  clientSecret: "your-twitter-client-secret",
  redirectUri: "https://yourapp.com/auth/twitter/callback",
  scope: "tweet.read users.read",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://twitter.com/i/oauth2/authorize",
    tokenUrl: "https://api.twitter.com/2/oauth2/token",
    userInfoUrl: "https://api.twitter.com/2/users/me",
  },
  validateUser: async (tokenPayload) => {
    return {
      id: tokenPayload.id,
      username: tokenPayload.username,
      name: tokenPayload.name,
      profile_image_url: tokenPayload.profile_image_url,
    };
  },
};
```

**Usage:**

```typescript
class TwitterAuthStrategy extends OAuth2AuthStrategy<Express.Request, any> {
  protected async fetchUser(decodedToken: any): Promise<any | null> {
    return decodedToken ? { id: decodedToken.id, username: decodedToken.username } : null;
  }
}

const twitterStrategy = new TwitterAuthStrategy(twitterAuthConfig, accessTokenHandler, refreshTokenHandler);
```

---

## **4. GitHub OAuth2 Example**

```typescript
const githubAuthConfig: OAuth2AuthStrategyConfig = {
  clientId: "your-github-client-id",
  clientSecret: "your-github-client-secret",
  redirectUri: "https://yourapp.com/auth/github/callback",
  scope: "read:user user:email",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
  },
  validateUser: async (tokenPayload) => {
    return {
      id: tokenPayload.id,
      email: tokenPayload.email,
      username: tokenPayload.login,
      avatar_url: tokenPayload.avatar_url,
    };
  },
};
```

**Usage:**

```typescript
class GitHubAuthStrategy extends OAuth2AuthStrategy<Express.Request, any> {
  protected async fetchUser(decodedToken: any): Promise<any | null> {
    return decodedToken ? { id: decodedToken.id, email: decodedToken.email } : null;
  }
}

const githubStrategy = new GitHubAuthStrategy(githubAuthConfig, accessTokenHandler, refreshTokenHandler);
```

---

## **5. Microsoft OAuth2 Example (Azure AD)**

```typescript
const microsoftAuthConfig: OAuth2AuthStrategyConfig = {
  clientId: "your-microsoft-client-id",
  clientSecret: "your-microsoft-client-secret",
  redirectUri: "https://yourapp.com/auth/microsoft/callback",
  scope: "openid profile email",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userInfoUrl: "https://graph.microsoft.com/v1.0/me",
  },
  validateUser: async (tokenPayload) => {
    return {
      id: tokenPayload.id,
      email: tokenPayload.mail || tokenPayload.userPrincipalName,
      displayName: tokenPayload.displayName,
    };
  },
};
```

**Usage:**

```typescript
class MicrosoftAuthStrategy extends OAuth2AuthStrategy<Express.Request, any> {
  protected async fetchUser(decodedToken: any): Promise<any | null> {
    return decodedToken ? { id: decodedToken.id, email: decodedToken.email } : null;
  }
}

const microsoftStrategy = new MicrosoftAuthStrategy(microsoftAuthConfig, accessTokenHandler, refreshTokenHandler);
```

---

## **6. LinkedIn OAuth2 Example**

```typescript
const linkedinAuthConfig: OAuth2AuthStrategyConfig = {
  clientId: "your-linkedin-client-id",
  clientSecret: "your-linkedin-client-secret",
  redirectUri: "https://yourapp.com/auth/linkedin/callback",
  scope: "r_liteprofile r_emailaddress",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://www.linkedin.com/oauth/v2/authorization",
    tokenUrl: "https://www.linkedin.com/oauth/v2/accessToken",
    userInfoUrl: "https://api.linkedin.com/v2/me",
  },
  validateUser: async (tokenPayload) => {
    return {
      id: tokenPayload.id,
      email: tokenPayload.emailAddress,
      firstName: tokenPayload.localizedFirstName,
      lastName: tokenPayload.localizedLastName,
    };
  },
};
```

**Usage:**

```typescript
class LinkedInAuthStrategy extends OAuth2AuthStrategy<Express.Request, any> {
  protected async fetchUser(decodedToken: any): Promise<any | null> {
    return decodedToken ? { id: decodedToken.id, email: tokenPayload.email } : null;
  }
}

const linkedinStrategy = new LinkedInAuthStrategy(linkedinAuthConfig, accessTokenHandler, refreshTokenHandler);
```
