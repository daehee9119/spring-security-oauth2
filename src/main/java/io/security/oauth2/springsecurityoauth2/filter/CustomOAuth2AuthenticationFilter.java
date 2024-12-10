package io.security.oauth2.springsecurityoauth2.filter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class CustomOAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String DEFAULT_FILTER_PROCESSING_URL = "/oauth2Login/**";

    private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private OAuth2AuthorizationSuccessHandler successHandler;

    private final Duration clockSkew = Duration.ofSeconds(3600);
    private final Clock clock = Clock.systemUTC();

    public CustomOAuth2AuthenticationFilter(DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
            OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
        super(DEFAULT_FILTER_PROCESSING_URL);
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;

        successHandler = (authorizedClient, principal, attributes) -> {
            this.oAuth2AuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal,
                    (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                    (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            System.out.println("authorizedClient=" + authorizedClient);
            System.out.println("principal=" + principal);
            System.out.println("attributes=" + attributes);
        };
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication == null) {
            authentication = new AnonymousAuthenticationToken("anonymous", "anonymous",
                    AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        }

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication.getName())
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);

        //refreshTOken - 권한 부여 타입 변경 안하고 실행
        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
                && authorizedClient.getRefreshToken() != null) {
            oAuth2AuthorizedClientManager.authorize(authorizeRequest);
        }

        //refreshToken - 권한 부여 타입 변경하고 실행
//        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
//                && authorizedClient.getRefreshToken() != null) {
//            oAuth2AuthorizedClientManager.authorize(authorizeRequest);
//            ClientRegistration clientRegistration = ClientRegistration
//                    .withClientRegistration(authorizedClient.getClientRegistration())
//                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();
//
//            OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(clientRegistration,
//                    authorizedClient.getPrincipalName(), authorizedClient.getAccessToken(),
//                    authorizedClient.getRefreshToken());
//
//            OAuth2AuthorizeRequest authorizeRequest2 = OAuth2AuthorizeRequest
//                    .withAuthorizedClient(oAuth2AuthorizedClient)
//                    .principal(authentication)
//                    .attribute(HttpServletRequest.class.getName(), request)
//                    .attribute(HttpServletResponse.class.getName(), response)
//                    .build();
//
//            authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest2);
//        }

        if (authorizedClient != null) {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);
            OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthoritySet = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

            OAuth2AuthenticationToken authenticationToken =
                    new OAuth2AuthenticationToken(oAuth2User, grantedAuthoritySet, clientRegistration.getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            successHandler.onAuthorizationSuccess(authorizedClient, authenticationToken, createAttributes(request, response));

            return authenticationToken;
        }
        return null;
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return clock.instant().isAfter(token.getExpiresAt().minus(clockSkew));
    }

    private static Map<String, Object> createAttributes(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(HttpServletRequest.class.getName(), servletRequest);
        attributes.put(HttpServletResponse.class.getName(), servletResponse);
        return attributes;
    }

}
