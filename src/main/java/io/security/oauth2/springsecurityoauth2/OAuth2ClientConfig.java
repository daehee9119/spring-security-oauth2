package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests((requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated());
        http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
        http.oauth2Login(authLogin -> authLogin.defaultSuccessUrl("/"));
//        http.oauth2Login(oauth2 -> oauth2.loginPage("/login"));
        return http.build();
   }
}