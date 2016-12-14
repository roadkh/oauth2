package com.road.pilot.security;

import com.google.common.collect.Sets;
import com.road.pilot.domain.CodeRole;
import com.road.pilot.domain.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Created by road on 16. 12. 12.
 */
public class CustomUserDetails implements UserDetails {

    private User user;

    @Getter
    private String id;

    private CustomUserDetails() {

    }

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = Sets.newHashSet();
        if(user.getRoles() != null && user.getRoles().size() > 0) {
            for(CodeRole userRole : user.getRoles()) {
                authorities.add(new SimpleGrantedAuthority(userRole.getId()));
            }
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
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
