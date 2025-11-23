package com.musabswe.spring_security_jwt.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data // It automatically generates:
//✔️ Getters for all fields
//✔️ Setters for all non-final fields
//✔️ toString() method
//✔️ equals() and hashCode() methods
//✔️ RequiredArgsConstructor (constructor for final fields)
@Builder // This enables the Builder Design Pattern, allowing you to build objects in a readable and flexible way.
@NoArgsConstructor
// Generates an empty constructor (no parameters). Useful when some frameworks (like Hibernate, JPA, Jackson) need a default constructor to create objects.
@AllArgsConstructor // Generates a constructor with all fields as parameters.
@Entity
@Table(name = "_user")
public class User implements UserDetails {

    @Id
    @GeneratedValue
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Override
//    used to return list of roles
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
