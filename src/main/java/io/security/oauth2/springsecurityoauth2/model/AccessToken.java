package io.security.oauth2.springsecurityoauth2.model;

import lombok.Data;

@Data
public class AccessToken {

    private String token;
    private String refreshToken;

}
