package io.security.oauth2.springsecurityoauth2.signature;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public abstract class SecuritySigner {

    public abstract String getJwtToken(UserDetails userDetails, JWK jwk) throws JOSEException;

    protected String getJwtTokenInternal(JWSSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {
        JWSHeader jwsHeader = new JWSHeader.Builder(
                ((JWSAlgorithm) jwk.getAlgorithm())).keyID(jwk.getKeyID()).build();
        List<String> authorities =
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("user")
                .issuer("http://lcoalhost:8081")
                .claim("username", user.getUsername())
                .claim("authority", authorities)
                .expirationTime(new Date(new Date().getTime() * 60 * 1000 * 5))
                .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(jwsSigner);

        return signedJWT.serialize();
    }

}
