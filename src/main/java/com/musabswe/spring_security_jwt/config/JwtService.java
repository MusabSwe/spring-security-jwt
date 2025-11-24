package com.musabswe.spring_security_jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "ec7e44696b7ae31003003533c4b192f020248d0b541eed3a54545841fa28ebfb";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //    generate token with userDetails only
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    //    generate token with userDetails and extra claims
    public String generateToken(
            Map<String, Object> extraClaims // will contain the claim
            , UserDetails userDetails // to pass userDetails from spring security framework
    ) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
//    compare between the token with user token
        final String username = extractUsername(token); // username should be unique and here username is the email
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //  used to extract all claims (Claims are pieces of information (data) about a user or a system, stored inside a JWT token which describe who the user is, what they can do, and other useful details.) in the token
    private Claims extractAllClaims(String token) {
        // signingKey is used to create signature part of
        // the JWT which is used to verify that the sender
        // of the JWT is who it claims to be and ensure
        // that the message was not changed along the way
//        The Signing key is used in conjunction with
//        sign-in algorithm specified in the JWT header
//        to create the signature the specific sign-in
//        algorithm and key size will depend on the security
//        requirement of your application and the level of trust
//        you have in the signing party
//        generate a new token or a secret key and I will use the
//        minimum assigning key of size 256 bits so we will
//        generate the secret key using online generator
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes); // must return SecretKey, not key
    }
}
