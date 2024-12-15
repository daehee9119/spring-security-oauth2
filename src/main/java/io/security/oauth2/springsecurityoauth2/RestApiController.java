package io.security.oauth2.springsecurityoauth2;

import java.util.List;

import io.security.oauth2.springsecurityoauth2.model.AccessToken;
import io.security.oauth2.springsecurityoauth2.model.Photo;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final RestTemplate restTemplate;

    @GetMapping("/token")
    public OAuth2AccessToken token(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient.getAccessToken();
    }

    @GetMapping("/photos")
    public List<Photo> photos(AccessToken accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken.getToken());
        HttpEntity<?> entity = new HttpEntity<>(headers);
        String url = "http://localhost:8082/photos";

        ResponseEntity<List<Photo>> response = restTemplate.exchange(url, HttpMethod.GET, entity,
                new ParameterizedTypeReference<List<Photo>>() {});

        return response.getBody();
    }


}
