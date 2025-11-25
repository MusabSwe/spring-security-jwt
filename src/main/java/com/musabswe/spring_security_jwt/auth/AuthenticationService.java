package com.musabswe.spring_security_jwt.auth;

import com.musabswe.spring_security_jwt.config.JwtService;
import com.musabswe.spring_security_jwt.user.Role;
import com.musabswe.spring_security_jwt.user.User;
import com.musabswe.spring_security_jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
// class where implement the methods of controller APIs
// sign up, sign-in
public class AuthenticationService {
    private final UserRepository userRepository; // @RequiredArgsConstructor will work if we add final to inject dependency by spring
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder() // from  @Builder annotation used to build an object where enables the Builder Design Pattern
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build(); // to create user out of the registerRequest
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        log.info("login call with Body: {} ", request);
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        ); // if the user or password is incorrect exception will throw
//        if both are correct, then it will generate a token
        log.info("successful login");
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        log.info("user found: {}", user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
