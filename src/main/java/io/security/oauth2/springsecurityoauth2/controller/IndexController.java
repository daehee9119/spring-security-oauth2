package io.security.oauth2.springsecurityoauth2.controller;

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/api/user")
    public Authentication getUser(Authentication authentication,
            @AuthenticationPrincipal Jwt principal) throws URISyntaxException {

        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
        String sub = authenticationToken.getTokenAttributes().get("sub").toString();
        String email = authenticationToken.getTokenAttributes().get("email").toString();
        String scope = authenticationToken.getTokenAttributes().get("scope").toString();

        String sub1 = principal.getClaim("sub").toString();
        String token = principal.getTokenValue();

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        RequestEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET, new URI("http://localhost:8082"));
        ResponseEntity<String> responseEntity = restTemplate.exchange(request, String.class);
        String body = responseEntity.getBody();

        return authentication;
    }
}
