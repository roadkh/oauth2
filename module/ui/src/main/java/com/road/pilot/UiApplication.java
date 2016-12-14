package com.road.pilot;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.Map;

/**
 * Created by road on 16. 11. 28.
 */
@SpringBootApplication
@EnableZuulProxy
@RestController
@Slf4j
public class UiApplication {

    @Autowired
    TokenStore tokenStore;

    @RequestMapping(value = "/cli/auth")
    public Authentication authentication(Authentication authentication) {
        log.info("authentication.getPrincipal() is {}", authentication.getPrincipal());
        return authentication;
    }

    @RequestMapping(value = "/cli/principal")
    public Principal principal(Principal principal) {
        OAuth2Authentication auth = (OAuth2Authentication)principal;
        auth.getUserAuthentication();
        return principal;
    }

    @RequestMapping(value = "/cli/accessToken")
    public Map<String, Object> accessToken(OAuth2AccessToken token, OAuth2Authentication auth) {
        if(token == null) {
            throw new RuntimeException("Token is null");
        }
        Map<String, Object> addInfo = token.getAdditionalInformation();
        return addInfo;
    }

    @RequestMapping(value = "/cli/fromToken")
    public Map<String, Object> fromToken(OAuth2Authentication auth) {

        OAuth2AuthenticationDetails accessToken = (OAuth2AuthenticationDetails) auth.getDetails();
        String tokenValue = accessToken.getTokenValue();
        OAuth2AccessToken accessToken1 = tokenStore.readAccessToken(tokenValue);
        Map<String, Object> addInfo = accessToken1.getAdditionalInformation();

//        Map<String, Object> tokenValueMap = jwtAccessTokenConverter.convertAccessToken(auth);
        return addInfo;
    }

    public static void main(String[] args) {
        SpringApplication.run(UiApplication.class, args);
    }


    @EnableOAuth2Sso
    @Configuration
    @Slf4j
    public static class WebClientSecurityConfiguration extends WebSecurityConfigurerAdapter {


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .logout().logoutUrl("/logout").and()
                    .authorizeRequests()
                    .antMatchers("/login", "/res1/pub**").permitAll()
                    .anyRequest().authenticated();

        }

        @Bean
        public JwtAccessTokenConverter accessTokenConverter(JwtAccessTokenConverter jwtAccessTokenConverter) {
            Assert.notNull(jwtAccessTokenConverter);
            DefaultAccessTokenConverter accessTokenConverter = (DefaultAccessTokenConverter)jwtAccessTokenConverter.getAccessTokenConverter();
            CustomUserAuthenticationConverter userAuthenticationConverter = new CustomUserAuthenticationConverter();
            accessTokenConverter.setUserTokenConverter(userAuthenticationConverter);
            jwtAccessTokenConverter.setAccessTokenConverter(accessTokenConverter);
            return jwtAccessTokenConverter;
        }

//        @Override
//        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//            auth.userDetailsService(userDetailsService());
//        }

        //        @Bean
//        public PrincipalExtractor principalExtractor() {
//            return new CustomPrincipalExtractor();
//        }
//
//        @Bean
//        public UserDetailsService userDetailsService(TokenStore tokenStore, OAuth2RestOperations restTemplate) {
//            return new CustomUserDetailsService(tokenStore, restTemplate);
//        }

    }

    @Component
    public static class CustomUserAuthenticationConverter extends DefaultUserAuthenticationConverter {
        @Override
        public Authentication extractAuthentication(Map<String, ?> map) {
            if(map != null && map.containsKey(USERNAME)) {
                String userName = (String)map.get(USERNAME);
                String userId = (String)map.get("user_id");

                Collection<? extends GrantedAuthority> authorities = getAuthorities(map);

                User user = new User(userId, userName, authorities);

                CustomUserDetails userDetails = new CustomUserDetails(user);
                return new UsernamePasswordAuthenticationToken(userDetails, "N/A", authorities);
            }
            return null;
        }

        private Collection<? extends GrantedAuthority> getAuthorities(Map<String, ?> map) {
            if (!map.containsKey(AUTHORITIES)) {
                return null;
            }
            Object authorities = map.get(AUTHORITIES);
            if (authorities instanceof String) {
                return AuthorityUtils.commaSeparatedStringToAuthorityList((String) authorities);
            }
            if (authorities instanceof Collection) {
                return AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                        .collectionToCommaDelimitedString((Collection<?>) authorities));
            }
            throw new IllegalArgumentException("Authorities must be either a String or a Collection");
        }
    }

    public static class User implements Serializable {
        private String id;
        private String name;
        private Collection<? extends GrantedAuthority> authorities;

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        public User(String id, String name, Collection<? extends GrantedAuthority> authorities) {
            this.id = id;
            this.name = name;
            this.authorities = authorities;
        }
    }

    public static class CustomUserDetails implements UserDetails {

        private User user;

        public CustomUserDetails(User user) {
            this.user = user;
        }

        public User getUser() {
            return this.user;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.user.getAuthorities();
        }

        @Override
        public String getPassword() {
            return "N/A";
        }

        @Override
        public String getUsername() {
            return this.user.getName();
        }

        @Override
        public boolean isAccountNonExpired() {
            return false;
        }

        @Override
        public boolean isAccountNonLocked() {
            return false;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return false;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }
    }
}
