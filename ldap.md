## **LDAP Authentication Strategy - Example (WIP)**

The `LdapStrategy` allows authentication via an LDAP server. It extends the base `CredentialBasedAuthStrategy` and provides methods for user authentication, authorization, and session management.

### **Installation**

Before using the LDAP strategy, ensure you have installed the necessary package:

```bash
npm install ldapjs
```

### **Example Usage**

```typescript
import { LdapStrategy, LdapStrategyConfig } from "./strategies/ldap-strategy";

const ldapConfig: LdapStrategyConfig = {
  ldapUrl: "ldap://ldap.example.com",
  baseDn: "ou=users,dc=example,dc=com",
  bindDn: "cn=admin,dc=example,dc=com",
  bindCredentials: "adminpassword",
  userFilter: "(uid={{identifier}})",
  groupFilter: "(memberUid={{identifier}})",
  mapUserAttributes: (entry) => ({
    id: entry.uid,
    fullName: entry.cn,
    email: entry.mail,
  }),
};

const ldapAuth = new LdapStrategy(ldapConfig);

async function authenticateUser(username: string, password: string) {
  try {
    const result = await ldapAuth.authenticate({ identifier: username, password });
    console.log("User authenticated:", result.user);
  } catch (error) {
    console.error("Authentication failed:", error.message);
  }
}
```

### **Features**

- Binds to the LDAP server using provided credentials.
- Retrieves user data based on LDAP search filters.
- Supports group membership verification (optional).
- Provides session management.
- Easily extendable and configurable.

### **Configuration Options**

| Option             | Description                                                  | Required |
|-------------------|--------------------------------------------------------------|----------|
| `ldapUrl`          | URL of the LDAP server                                       | ✅        |
| `baseDn`           | Base DN (Distinguished Name) for searching users             | ✅        |
| `bindDn`           | DN used to bind to the LDAP server                           | ✅        |
| `bindCredentials`  | Password for the binding DN                                  | ✅        |
| `userFilter`       | LDAP filter to find users, e.g. `"(uid={{identifier}})"`     | ✅        |
| `groupFilter`      | (Optional) LDAP filter to check group membership             | ❌        |
| `mapUserAttributes`| Function to map LDAP user attributes to application structure| ❌        |
