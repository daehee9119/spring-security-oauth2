package io.security.oauth2.springsecurityoauth2.filter.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import io.security.oauth2.springsecurityoauth2.dto.LoginDto;
import io.security.oauth2.springsecurityoauth2.signature.SecuritySigner;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final SecuritySigner securitySigner;
    private final JWK jwk;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws
            AuthenticationException {

        ObjectMapper objectMapper = new ObjectMapper();
        LoginDto loginDto = null;

        try {
            loginDto = objectMapper.readValue(req.getInputStream(), LoginDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Authentication authResult)
            throws ServletException, IOException {
        //        SecurityContextHolder.getContext().setAuthentication(authResult);
        //        getSuccessHandler().onAuthenticationSuccess(request, response, authResult);

        User user = (User) authResult.getPrincipal();
        String jwtToken;

        try {
            jwtToken = securitySigner.getJwtToken(user, jwk);
            response.addHeader("Authorization", "Bearer " + jwtToken);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

}
