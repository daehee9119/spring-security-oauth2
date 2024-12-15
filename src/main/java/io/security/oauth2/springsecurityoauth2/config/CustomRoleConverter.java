package io.security.oauth2.springsecurityoauth2.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {

        String scopes = jwt.getClaimAsString("scope");
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");

        if(scopes == null || realmAccess == null) {
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorityList1 = Arrays.stream(scopes.split(" "))
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        List<GrantedAuthority> authorityList2 = ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorityList1.addAll(authorityList2);

        return authorityList1;
    }
}
