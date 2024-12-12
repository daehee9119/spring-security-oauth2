package io.security.oauth2.springsecurityoauth2.signature;

import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.core.userdetails.UserDetails;

public class MacSecuritySigner extends SecuritySigner{

    @Override
    public String getToken(UserDetails userDetails, JWK jwk) throws KeyLengthException {

        MACSigner jwsSigner = new MACSigner(((OctetSequenceKey) jwk).toSecretKey());

        return "";
    }

}
