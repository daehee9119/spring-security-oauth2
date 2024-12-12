package io.security.oauth2.springsecurityoauth2.signature;

import com.nimbusds.jose.jwk.JWK;
import org.springframework.security.core.userdetails.UserDetails;

public abstract class SecuritySigner {

    public abstract String getToken(UserDetails userDetails, JWK jwk);

}
