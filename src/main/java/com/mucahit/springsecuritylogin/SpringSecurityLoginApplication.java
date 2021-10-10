package com.mucahit.springsecuritylogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class SpringSecurityLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityLoginApplication.class, args);
    }

}
