package com.musabswe.spring_security_jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    public String extractUsername(String token) {

        return null;
    }

    private Claims extractAllClaims(String token) {
        return null;
    }
}
