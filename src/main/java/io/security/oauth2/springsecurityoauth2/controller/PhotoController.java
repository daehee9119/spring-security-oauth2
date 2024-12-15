package io.security.oauth2.springsecurityoauth2.controller;

import java.util.List;

import io.security.oauth2.springsecurityoauth2.model.Photo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

    @GetMapping("/remotePhotos")
    public List<Photo> remotePhotos() {
        return List.of(
                getPhoto("Remote 1", "Remote Photo 1 Title", "Remote Photo is nice", "Remote user1"),
                getPhoto("Remote 2", "Remote Photo 2 Title", "Remote Photo 2 is awesome", "Remote user2"));
    }

    @GetMapping("/photos")
    public List<Photo> photos() {
        return List.of(
                getPhoto("1", "Photo 1 Title", "Photo is nice", "user1"),
                getPhoto("2", "Photo 2 Title", "Photo 2 is awesome", "user2"));
    }

    private Photo getPhoto(String photoId, String title, String desc, String userId) {
        return Photo.builder()
                .photoId(photoId)
                .photoTitle(title)
                .photoDescription(desc)
                .userId(userId)
                .build();
    }

}
