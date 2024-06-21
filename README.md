
# Springboot App that authenticates against multiple realms of Keycloak
- Treat each keycloak realm as an independent tenant.
- A backend application that serves multiple tenants now needs to identify tokens from multipe issuers. (In keycloak every realm gets a different issuer URI.)
- This app demo's how to do that - uses spring security documentation as a base https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html#oauth2resourceserver-multitenancy
- Tenants iss claims are hardcoded but for production they can easily be fetched dynamically from a configmap or DB, app does not need to restart. 
