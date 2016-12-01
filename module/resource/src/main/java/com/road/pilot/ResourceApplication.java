package com.road.pilot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2RestOperationsConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.security.Principal;
import java.util.ArrayList;
import java.util.UUID;

/**
 * Created by road on 16. 11. 29.
 */
@SpringBootApplication
@RestController
@EnableResourceServer
public class ResourceApplication extends OAuth2RestOperationsConfiguration {

    @Autowired
    private OAuth2RestTemplate restTemplate;

    @Bean
    public OAuth2RestTemplate restTemplate(UserInfoRestTemplateFactory factory) {
        return factory.getUserInfoRestTemplate();
    }

    @RequestMapping("/")
    public Message home(Principal principal) {
        String msg = "This is Test Resource Application.";
        String name = principal.getName();
        msg += " Good luck " + name + ".";
        return new Message(msg);
    }

    @RequestMapping("/fromRes2")
    public Message fromRes2() {
        String url = "http://localhost:8082/res2/";
        ResponseEntity<Message> res = restTemplate.exchange(url, HttpMethod.GET, null, Message.class);
        Message message = null;
        if(res.getStatusCode() == HttpStatus.OK) {
            message = res.getBody();
        }
        return message;
    }


    @RequestMapping("/pub")
    public Message publicMsg() {
        String msg = "This is Public Msg from Resource Application.";

        return new Message(msg);
    }

    public static void main(String[] args) {
        SpringApplication.run(ResourceApplication.class, args);
    }

//    @Component
//    @Order(Ordered.HIGHEST_PRECEDENCE)
//    protected static class WorkaroundRestTemplateCustomizer implements UserInfoRestTemplateCustomizer {
//        @Override
//        public void customize(OAuth2RestTemplate template) {
//            template.setInterceptors(new ArrayList<>(template.getInterceptors()));
//        }
//
//    }



//    @Configuration
//    protected static class OAuth2ClientConfiguration {
//        @Bean
//        @ConfigurationProperties("security.oauth2.client")
//        public ClientCredentialsResourceDetails clientCredentialsResourceDetails() {
//            return new ClientCredentialsResourceDetails();
//        }
//
//        @Bean
//        public OAuth2RestTemplate restTemplate() {
//            AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
//            return new OAuth2RestTemplate(clientCredentialsResourceDetails(), new DefaultOAuth2ClientContext(accessTokenRequest));
//        }
//    }

    @Configuration
    protected static class MvcSecurityConfiguration extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/pub**").permitAll()
                    .antMatchers("/**").authenticated();
        }

        //        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http
//                    .authorizeRequests()
//                    .antMatchers("/pub**").permitAll()
//                    .antMatchers("/**").authenticated();
//        }
    }

}

class Message {
    private String id = UUID.randomUUID().toString();
    private String content;

    Message() {
    }

    public Message(String content) {
        this.content = content;
    }

    public String getId() {
        return id;
    }

    public String getContent() {
        return content;
    }
}