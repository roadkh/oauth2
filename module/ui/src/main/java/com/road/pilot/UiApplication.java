package com.road.pilot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

/**
 * Created by road on 16. 11. 28.
 */
@SpringBootApplication
@EnableZuulProxy
@RestController
public class UiApplication {

    @Autowired
    JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired
    TokenStore tokenStore;

    @RequestMapping(value = "/cli/user")
    public Principal principal(Principal principal) {
        return principal;
    }

    @RequestMapping(value = "/fromToken")
    public Map<String, Object> fromToken(OAuth2Authentication auth) {
        OAuth2AuthenticationDetails accessToken = (OAuth2AuthenticationDetails)auth.getDetails();
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
    public static class WebClientSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .logout().logoutUrl("/logout").and()
                        .authorizeRequests()
                        .antMatchers("/login", "/res1/pub**").permitAll()
                        .anyRequest().authenticated();
        }


    }
//    @Configuration
//    public static class MvcSecurityConfiguration extends WebSecurityConfigurerAdapter {
//
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http
//                    .authorizeRequests()
////                        .antMatchers("/**").authenticated()
//                    .antMatchers("/res1/pub/**").permitAll()
//                    .antMatchers("/**").authenticated();
//        }
//    }
}
