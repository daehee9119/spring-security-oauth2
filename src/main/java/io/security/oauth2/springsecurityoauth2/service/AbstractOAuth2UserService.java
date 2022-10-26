package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.common.enums.OAuth2Config;
import io.security.oauth2.springsecurityoauth2.common.util.OAuth2Utils;
import io.security.oauth2.springsecurityoauth2.model.users.*;
import io.security.oauth2.springsecurityoauth2.model.users.impl.GoogleUser;
import io.security.oauth2.springsecurityoauth2.model.users.impl.KakaoUser;
import io.security.oauth2.springsecurityoauth2.model.users.impl.NaverUser;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Getter
public abstract class AbstractOAuth2UserService {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest){

        User user = userRepository.findByUsername(providerUser.getUsername());

        if(user == null){
            ClientRegistration clientRegistration = userRequest.getClientRegistration();
            userService.register(clientRegistration.getRegistrationId(),providerUser);
        }else{
            System.out.println("userRequest = " + userRequest);
        }
    }

    public ProviderUser providerUser(ClientRegistration clientRegistration, OAuth2User oAuth2User){

        String registrationId = clientRegistration.getRegistrationId();

        if(registrationId.equals(OAuth2Config.SocialType.GOOGLE.name())){
            return new GoogleUser(OAuth2Utils.getMainAttributes(oAuth2User), oAuth2User,clientRegistration);

        }
        else if(registrationId.equals(OAuth2Config.SocialType.NAVER.name())){
            return new NaverUser(OAuth2Utils.getSubAttributes(oAuth2User,"response"), oAuth2User,clientRegistration);

        }
        else if(registrationId.equals(OAuth2Config.SocialType.KAKAO.name())){
            return new KakaoUser(OAuth2Utils.getOtherAttributes(oAuth2User,"kakao_account","profile"), oAuth2User,clientRegistration);
        }

        return null;
    }
}