package com.road.pilot;

import org.h2.server.web.DbStarter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;

/**
 * Created by road on 16. 12. 1.
 */
@SpringBootApplication
public class H2DbApplication {

    @Bean
    public DbStarter dbStarter() {
        return new DbStarter();
    }

    @Bean
    public ServletContextInitializer initializer() {
        return servletContext -> {
            servletContext.setInitParameter("db.user", "sa");
            servletContext.setInitParameter("db.password", "");
            servletContext.setInitParameter("db.tcpServer", "-tcpAllowOthers");
        };
    }

    public static void main(String[] args) {
        SpringApplication.run(H2DbApplication.class, args);
    }
}
