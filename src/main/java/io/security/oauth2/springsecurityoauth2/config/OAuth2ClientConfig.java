package io.security.oauth2.springsecurityoauth2.config;

import io.security.oauth2.springsecurityoauth2.filter.CustomOAuth2AuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(requests -> requests.antMatchers("/", "/oauth2Login", "/client").permitAll()
                        .anyRequest().authenticated())
                //                .oauth2Login(Customizer.withDefaults())
                .oauth2Client(Customizer.withDefaults());
        http.addFilterBefore(customOAuth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
   }

    private CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() {
        CustomOAuth2AuthenticationFilter auth2AuthenticationFilter = new CustomOAuth2AuthenticationFilter(
                oAuth2AuthorizedClientManager, authorizedClientRepository);
        auth2AuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/home");
        });
        return auth2AuthenticationFilter;
    }

}
