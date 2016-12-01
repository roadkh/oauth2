package com.road.pilot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by road on 16. 11. 28.
 */
@SpringBootApplication
@EnableZuulProxy
public class UiApplication
//        extends WebSecurityConfigurerAdapter
{

//    @RequestMapping(value = "/user")
//    public Principal principal(Principal principal) {
//        return principal;
//    }

    public static void main(String[] args) {
        SpringApplication.run(UiApplication.class, args);
    }


    @EnableOAuth2Sso
    @Configuration
    public static class WebClientSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .logout().and()
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
