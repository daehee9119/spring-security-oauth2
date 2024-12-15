package io.security.oauth2.springsecurityoauth2.model;

import lombok.Data;

@Data
public class Photo {
    private String photoId;
    private String photoTitle;
    private String photoDescription;
    private String userId;
}
