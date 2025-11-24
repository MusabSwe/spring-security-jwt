package com.musabswe.spring_security_jwt.config;

import com.musabswe.spring_security_jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private UserRepository userRepository;

    //    always @Bean method is public
    @Bean
    public UserDetailsService userDetailsService() {
//        since findByEmail optional method, so we add orElseThrow so when the user not found throw an exception error
        return username -> userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User Not Found"));
    }
}
