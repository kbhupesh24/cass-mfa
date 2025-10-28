# Azure Entra (Azure AD) JWT Integration Reference

This document explains how to configure Azure Entra (Azure AD) to issue JWT tokens with group and role claims for use with the Cassandra security provider.

---

## 1. How Groups and Roles Appear in JWTs

- **Groups**: Azure AD can include a `groups` claim in the JWT, listing the object IDs of groups the user/service principal belongs to.
- **Roles**: If you define app roles in your Azure AD app registration and assign them, the JWT will include a `roles` claim.
- **Custom Claims**: You can configure additional claims via the Azure Portal (App Registration → Token configuration → Optional claims).

### How to Ensure Groups/Roles Are Included
1. **App Registration**: In Azure Portal, go to your App Registration.
2. **Token Configuration**: Add 'Group' and/or 'Role' claims as optional claims.
3. **Manifest**: You can also edit the manifest to always emit these claims.
4. **Assignments**: Assign users or service principals to the relevant groups/roles.

---

## 2. How to Register a Client Application and Get a Client ID & Secret

1. **Register a New Application**
   - Go to Azure Portal → Azure Active Directory → App registrations → New registration.
   - Name your app (e.g., `CassandraClientApp`).
   - Set the supported account types as needed.
   - Click 'Register'.

2. **Create a Client Secret**
   - In your app registration, go to 'Certificates & secrets'.
   - Click 'New client secret', add a description, and set an expiry.
   - Save the generated secret value (you won't see it again).

3. **Get the Client ID and Tenant ID**
   - On the app registration 'Overview' page, copy the 'Application (client) ID' and 'Directory (tenant) ID'.

4. **(Optional) Create a Service Principal**
   - This is done automatically when you register the app, but you can also use Azure CLI:
     ```bash
     az ad sp create --id <client-id>
     ```

5. **Assign API Permissions**
   - Go to 'API permissions' → 'Add a permission'.
   - Add the required Microsoft Graph or custom API permissions.
   - Grant admin consent if needed.

---

## 3. Using the JWT in Cassandra Clients

- Use a custom AuthProvider (see main README) to extract the JWT and send it as the password ("Bearer <token>").
- No manual token copy/paste is needed if you automate token acquisition.

---

## 4. Troubleshooting

- If groups/roles are missing from the JWT, check your app registration's Token Configuration and Manifest.
- Ensure the client app has the necessary API permissions and admin consent.
- The `scope` parameter should match the resource you are authenticating to (e.g., Azure SQL, custom API, etc.).

---

## Cluster-Aware Roles Mapping

- The security provider now scopes roles-to-keyspace mapping by Cassandra cluster name (from `DatabaseDescriptor.getClusterName()`).
- In your `security.yaml`, use:
  ```yaml
  roles:
    clusters:
      <cluster_name>:
        my_keyspace: MYKS_<CLUSTER>
  ```
- This ensures the same keyspace name in different clusters maps to different group prefixes and avoids cross-cluster permission leakage.
- No need to set `CASS_ENV` or use an environment property.

---

## References
- [Azure AD: Add optional claims to your ID tokens](https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims)
- [Azure AD: Configure group claims](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-group-claims)
- [MSAL4J Documentation](https://github.com/AzureAD/microsoft-authentication-library-for-java)
- [Azure CLI: Create a service principal](https://learn.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli)
