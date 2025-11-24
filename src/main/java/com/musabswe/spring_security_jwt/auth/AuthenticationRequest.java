package com.musabswe.spring_security_jwt.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
// login
public class AuthenticationRequest {

    private String email;
    String password;
}
