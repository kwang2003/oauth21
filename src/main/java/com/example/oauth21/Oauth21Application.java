package com.example.oauth21;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * @author kevin
 */
@SpringBootApplication
@EnableRedisHttpSession
public class Oauth21Application {

    public static void main(String[] args) {
        SpringApplication.run(Oauth21Application.class, args);
    }

}
