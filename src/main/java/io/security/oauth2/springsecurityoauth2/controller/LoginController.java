package io.security.oauth2.springsecurityoauth2.controller;

import java.time.Clock;
import java.time.Duration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @Autowired
    private DefaultOAuth2AuthorizedClientManager defaultOAuth2AuthorizedClientManager;
    @Autowired
    private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    private final Duration clockSkew = Duration.ofSeconds(3600);
    private final Clock clock = Clock.systemUTC();

//     필터 없이 controller 에서 처리
    @GetMapping("/oauth2Login")
    public String oauth2Login(HttpServletRequest request, Model model, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication.getName())
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizationSuccessHandler oAuth2AuthorizationSuccessHandler = (authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal,
                    (HttpServletRequest)attributes.get(HttpServletRequest.class.getName()),
                    (HttpServletResponse)attributes.get(HttpServletResponse.class.getName()));
            System.out.println("authorizedClient="+authorizedClient);
            System.out.println("principal="+principal);
            System.out.println("attributes="+attributes);
        };
        defaultOAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(oAuth2AuthorizationSuccessHandler);

        OAuth2AuthorizedClient authorizedClient = defaultOAuth2AuthorizedClientManager.authorize(authorizeRequest);

        //refreshTOken - 권한 부여 타입 변경 안하고 실행
//        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())  && authorizedClient.getRefreshToken() != null) {
//            defaultOAuth2AuthorizedClientManager.authorize(authorizeRequest);
//        }


        //refreshToken - 권한 부여 타입 변경하고 실행
        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())  && authorizedClient.getRefreshToken() != null) {
            defaultOAuth2AuthorizedClientManager.authorize(authorizeRequest);
            ClientRegistration clientRegistration = ClientRegistration
                    .withClientRegistration(authorizedClient.getClientRegistration())
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();

            OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(clientRegistration,
                    authorizedClient.getPrincipalName(), authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());

            OAuth2AuthorizeRequest authorizeRequest2 = OAuth2AuthorizeRequest
                    .withAuthorizedClient(oAuth2AuthorizedClient)
                    .principal(authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build();

            authorizedClient = defaultOAuth2AuthorizedClientManager.authorize(authorizeRequest2);
        }

        // client_crednetial 은 서버대서버 통신에 필요한 access token 만 있으면 장땡임
        model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("refreshToken", authorizedClient.getRefreshToken().getTokenValue());

        /*
        // 이건 최종 인증에만 필요한 것이기 때문에 client-credential 에서는 의미 없다. client 자체가 user 니까
        if (Objects.nonNull(authorizedClient)) {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);
            OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthoritySet = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

            OAuth2AuthenticationToken authenticationToken =
                    new OAuth2AuthenticationToken(oAuth2User,
                            grantedAuthoritySet,
                            clientRegistration.getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            model.addAttribute("oAuth2AuthenticationToken", authenticationToken);
        }*/

        return "home";
    }
    private boolean hasTokenExpired(OAuth2Token token) {
        return clock.instant().isAfter(token.getExpiresAt().minus(clockSkew));
    }

    // Custom login 필터로 처리
    @GetMapping("/v2/oauth2Login")
    public String oauth2LoginV2(HttpServletRequest request, Model model, HttpServletResponse response){
        return "home";
    }

    @GetMapping("/logout")
    public String oauth2Logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response){
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);
        return "redirect:/";
    }



}
