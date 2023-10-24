package com.example.oauth21.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class DbUserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
        String password = "111111";
        String encodedPassword = passwordEncoder.encode(password);
        User user = new User("admin",encodedPassword,authorities);
        return user;
    }
}
