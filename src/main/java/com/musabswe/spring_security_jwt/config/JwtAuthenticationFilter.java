package com.musabswe.spring_security_jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    //     so we can intercept every request and extract data
//    for example from the request and provide new data
//    within the response so for example I want to add
//    a header to at response we can do it using this once
//    per request filter
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, // is our request
            @NonNull HttpServletResponse response, // is our response
            @NonNull FilterChain filterChain // is the chain of responsibility design pattern , so it will contain the list of other filters that we need to execute
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7); // starts after 7 since Bearer with space 7 chars
        userEmail = jwtService.extractUsername(jwt); // used to extract the userEmail from JWT token in Spring Security unique identifier call it username

//        check if the user is authenticated or not
//        SecurityContextHolder.getContext().getAuthentication() == null means user is not authenticated
//        when we have userEmail and user not authenticated
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            we get userDetails from the DB
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
//          check if the token and user are valid we will update security context
            if (jwtService.isTokenValid(jwt, userDetails)) {
//          will create an object of type a username,
//          password authentication token by passing
//          userDetails, credentials, and authorities
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
// reinforce the auth token with details of our request
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// update the auth token
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
//        after if statement do not forget to call filterChain
//        to pass the hand to the next filter
        filterChain.doFilter(request, response);
    }
}
