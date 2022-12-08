package com.example.security.security;

import com.google.common.collect.Sets;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.security.security.ApplicationUserPermission.*;

@AllArgsConstructor
@Getter
public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
//    ADMIN(Arrays.stream(ApplicationUserPermission.values()).collect(Collectors.toSet()));
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    MODERATOR(Sets.newHashSet(COURSE_READ, STUDENT_READ)); // (ADMINTRAINEE)

    private final Set<ApplicationUserPermission> permissions;

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
/*    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(
                        permission -> {
                            System.out.println(permission.getPermission());
                            return new SimpleGrantedAuthority(permission.getPermission());
                        }
                )
                .collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        System.out.println(this.name());
        System.out.println();
        return permissions;
    }*/
}
