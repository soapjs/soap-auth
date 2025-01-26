# **SAML Authentication Strategy (Google Workspace) - Example (WIP)**

This guide provides an example of implementing SAML authentication without Passport.js, using Google Workspace as the Identity Provider (IdP).

---

## **1. Installation**

Install the required dependencies:

```bash
npm install samlify xml-crypto express
```

---

## **2. Configure Google Workspace (IdP)**

To set up Google as the Identity Provider (IdP):

1. **Sign in to Google Admin Console** ([admin.google.com](https://admin.google.com/)).
2. Navigate to **Apps > Web and Mobile Apps > Add App > Custom SAML App**.
3. Copy the following details from Google and save them in your project:
   - **SSO URL** (Single Sign-On Service)
   - **Entity ID** (Issuer)
   - **X.509 Certificate** (for validating SAML assertions)
4. Configure the ACS URL (Assertion Consumer Service) to point to your application, e.g.:
   ```
   https://your-app.com/auth/saml/callback
   ```
5. Map attributes such as:
   - `email`
   - `first_name`
   - `last_name`

Save Google IdP metadata as `google-idp-metadata.xml` in your project.

---

## **3. Project Structure**

```
/saml-auth
  ├── config/
  │   ├── google-idp-metadata.xml  # Metadata from Google Admin
  │   ├── sp-private-key.pem        # Service provider private key
  │   ├── sp-public-cert.pem        # Service provider public certificate
  ├── src/
  │   ├── saml-strategy.ts          # SAML authentication strategy
  │   ├── server.ts                  # Express server to handle requests
  ├── package.json
  ├── README.md
```

---

## **4. Implementing the SAML Strategy**

### **saml-strategy.ts**

```typescript
import * as saml from "samlify";
import * as fs from "fs";

export class SAMLStrategy {
  private serviceProvider: saml.ServiceProviderInstance;
  private identityProvider: saml.IdentityProviderInstance;

  constructor() {
    // Load IdP metadata (from Google)
    this.identityProvider = saml.IdentityProvider({
      metadata: fs.readFileSync("./config/google-idp-metadata.xml", "utf-8"),
      isAssertionEncrypted: false,
      wantAuthnRequestsSigned: true,
    });

    // Configure the Service Provider (our application)
    this.serviceProvider = saml.ServiceProvider({
      entityID: "https://your-app.com/metadata",
      assertionConsumerService: [
        {
          Binding: saml.Constants.namespace.post,
          Location: "https://your-app.com/auth/saml/callback",
        },
      ],
      privateKey: fs.readFileSync("./config/sp-private-key.pem", "utf-8"),
    });
  }

  /**
   * Generates SAML login URL to redirect users to Google Workspace SSO
   * @returns {Promise<string>} SSO Login URL
   */
  async getLoginUrl(): Promise<string> {
    const { context } = await this.serviceProvider.createLoginRequest(
      this.identityProvider,
      "redirect"
    );
    return context; // SSO login URL for redirecting user
  }

  /**
   * Handles SAML response from Google and extracts user info.
   * @param {object} requestBody - The HTTP POST body containing SAMLResponse
   * @returns {Promise<object>} Parsed user data
   */
  async handleSamlResponse(requestBody: any): Promise<object> {
    if (!requestBody.SAMLResponse) {
      throw new Error("Missing SAML response.");
    }

    const { extract } = await this.serviceProvider.parseLoginResponse(
      this.identityProvider,
      "post",
      requestBody
    );

    return {
      email: extract.attributes.email,
      firstName: extract.attributes.first_name,
      lastName: extract.attributes.last_name,
    };
  }
}
```

---

## **5. Handling authentication in Express.js**

### **server.ts**

```typescript
import express from "express";
import { SAMLStrategy } from "./saml-strategy";

const app = express();
const samlAuth = new SAMLStrategy();

app.get("/auth/saml/login", async (req, res) => {
  try {
    const loginUrl = await samlAuth.getLoginUrl();
    res.redirect(loginUrl);
  } catch (error) {
    res.status(500).send("Error generating login request.");
  }
});

app.post("/auth/saml/callback", express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const userData = await samlAuth.handleSamlResponse(req.body);
    res.json({ message: "Authentication successful", user: userData });
  } catch (error) {
    res.status(401).send("Authentication failed");
  }
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```

---

## **6. Running the Application**

1. Start the server:

   ```bash
   node dist/server.js
   ```

2. Open the browser and go to:

   ```bash
   http://localhost:3000/auth/saml/login
   ```

   You will be redirected to Google for login.

3. After successful login, you will be redirected to the callback URL, and your user information will be displayed.

---

## **7. Additional Features**

You can extend the SAML strategy with:

1. **Single Logout (SLO) Support**
   - Implement an endpoint to handle logout requests from the IdP.

2. **Custom Attribute Mapping**
   - Customize user attributes in the response (e.g. department, roles).

3. **Multi-IdP Support**
   - Allow configuration for multiple SAML providers dynamically.

4. **Session Management**
   - Store authenticated user session in Redis or JWT.

---

## **8. Environment Variables Example**

To keep sensitive data secure, use environment variables:

```
SP_ENTITY_ID=https://your-app.com/metadata
SP_CALLBACK_URL=https://your-app.com/auth/saml/callback
SP_PRIVATE_KEY_PATH=./config/sp-private-key.pem
IDP_METADATA_PATH=./config/google-idp-metadata.xml
```

And access them in code like this:

```typescript
import dotenv from "dotenv";
dotenv.config();

const spEntityId = process.env.SP_ENTITY_ID;
const callbackUrl = process.env.SP_CALLBACK_URL;
```

---

## **9. Security Considerations**

1. **Always validate the SAML response signature to prevent tampering.**
2. **Rotate the private keys regularly and store them securely.**
3. **Monitor SAML authentication logs for suspicious activity.**

---

## **10. Conclusion**

This guide provided a simple yet powerful way to implement SAML authentication without relying on external frameworks like Passport.js. The setup allows easy integration with Google Workspace while ensuring flexibility and control over the authentication process.

---

### **11. Useful Resources**

- [Google Workspace SAML Setup](https://support.google.com/a/answer/6087519?hl=en)
- [samlify npm package](https://www.npmjs.com/package/samlify)
- [SAML Explained](https://www.okta.com/identity-101/what-is-saml/)
