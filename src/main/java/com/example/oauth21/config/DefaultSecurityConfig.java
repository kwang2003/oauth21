package com.example.oauth21.config;

import com.example.oauth21.federation.FederatedIdentityAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.1
 */
@Slf4j
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig{
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Bean
    public AuthenticationManager configProviders(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/login")
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .loginPage("/login")
                                .successHandler(authenticationSuccessHandler())
                );

        return http.build();
    }
    // @formatter:on

    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }

    @Bean
    public SessionRegistry sessionRegistry(RedisTemplate redisTemplate) {
        return new SpringSessionBackedSessionRegistry(new RedisIndexedSessionRepository(redisTemplate));
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

}