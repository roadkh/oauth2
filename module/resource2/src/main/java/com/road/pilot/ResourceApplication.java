package com.road.pilot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.UUID;

/**
 * Created by road on 16. 11. 30.
 */
@SpringBootApplication
@RestController
@EnableResourceServer
public class ResourceApplication {

    @RequestMapping("/")
    public Message home(Principal principal) {
        String msg = "This is Test Resource Application Number 2.";
        String name = principal.getName();
        msg += " Good luck " + name + ".";
        return new Message(msg);
    }

    @RequestMapping("/pub")
    public Message publicMsg() {
        String msg = "This is Public Msg from Resource 2 Application.";

        return new Message(msg);
    }


    public static void main(String[] args) {
        SpringApplication.run(ResourceApplication.class, args);
    }

    @Configuration
    protected static class MvcSecurityConfiguration extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/pub**").permitAll()
                    .antMatchers("/**").authenticated();
        }

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            resources.resourceId("oauth_resource");
        }
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

