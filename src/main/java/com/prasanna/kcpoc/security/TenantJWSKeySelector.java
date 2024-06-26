package com.prasanna.kcpoc.security;

import java.net.URL;
import java.security.Key;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;


@Component
public class TenantJWSKeySelector
    implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

	// private final TenantRepository tenants;
	private final Map<String, JWSKeySelector<SecurityContext>> selectors = new ConcurrentHashMap<>();

	// public TenantJWSKeySelector(TenantRepository tenants) {
	// 	this.tenants = tenants;
	// }

	@Override
	public List<? extends Key> selectKeys(JWSHeader jwsHeader, JWTClaimsSet jwtClaimsSet, SecurityContext securityContext)
			throws KeySourceException {
		return this.selectors.computeIfAbsent(toTenant(jwtClaimsSet), this::fromTenant)
				.selectJWSKeys(jwsHeader, securityContext);
	}

	private String toTenant(JWTClaimsSet claimSet) {
		return (String) claimSet.getClaim("iss");
	}

	private JWSKeySelector<SecurityContext> fromTenant(String tenant) {
		// return Optional.ofNullable(this.tenants.findById(tenant))
		//         .map(t -> t.getAttrbute("jwks_uri"))
		// 		.map(this::fromUri)
		// 		.orElseThrow(() -> new IllegalArgumentException("unknown tenant"));
        if("http://localhost:8180/realms/foo".equals(tenant)){
            return this.fromUri("http://localhost:8180/realms/foo/protocol/openid-connect/certs");
        }
        else if("http://localhost:8180/realms/bar".equals(tenant)){
            return this.fromUri("http://localhost:8180/realms/bar/protocol/openid-connect/certs");
        }
        return null;
	}

	private JWSKeySelector<SecurityContext> fromUri(String uri) {
		try {
			return JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(new URL(uri));
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}
}