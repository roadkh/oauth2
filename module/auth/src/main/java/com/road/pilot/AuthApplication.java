package com.road.pilot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.token.JdbcClientTokenServices;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by road on 16. 11. 28.
 */
@SpringBootApplication
@RestController
@SessionAttributes("authorizationRequest")
@EnableResourceServer
public class AuthApplication {

    @RequestMapping(value = "/user")
    public Principal principal(Principal principal) {
        return principal;
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

    @Configuration
    public static class MvcConfiguration extends WebMvcConfigurerAdapter {
        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("/login").setViewName("login");
        }
    }

    @Configuration
    @Order(-20)
    public static class HttpSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.httpBasic()
                    .and()
                    .requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
                    .and()
                    .authorizeRequests().anyRequest().authenticated()
            .and()
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.parentAuthenticationManager(authenticationManager);
        }
    }

    @Configuration
    @EnableAuthorizationServer
    public static class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks")
                    , "oauthpilot".toCharArray()).getKeyPair("pilot");
            converter.setKeyPair(keyPair);
            return converter;
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.jdbc(dataSource);
//                    .withClient("pilot")
//                    .secret("pilotSecret")
//                    .authorizedGrantTypes("authorization_code", "refresh_token", "password")
//                    .scopes("openid", "auth_user").autoApprove(false);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));
            endpoints.authenticationManager(authenticationManager)
//                    .accessTokenConverter(jwtAccessTokenConverter())
//                    .accessTokenConverter(new DefaultAccessTokenConverter())
                    .tokenStore(jdbcTokenStore())
                    .approvalStore(approvalStore())
                    .tokenEnhancer(tokenEnhancerChain)
                    .authorizationCodeServices(authorizationCodeServices())
            ;
        }

        @Autowired
        DataSource dataSource;

        @Bean
        public JdbcAuthorizationCodeServices authorizationCodeServices() {
            return new JdbcAuthorizationCodeServices(dataSource);
        }

        @Bean
        public JdbcTokenStore jdbcTokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        @Bean
        public ApprovalStore approvalStore() {
            return new JdbcApprovalStore(dataSource);
        }

        @Bean
        public TokenEnhancer tokenEnhancer() {
            return new CustomTokenEnhancer();
        }
    }

    public static class CustomTokenEnhancer implements TokenEnhancer {
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            Map<String, Object> additionalInfo = new HashMap<>();
            additionalInfo.put("test_data", "test_data");
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
            return accessToken;
        }
    }
}
