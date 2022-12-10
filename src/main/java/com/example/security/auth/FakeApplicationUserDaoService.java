package com.example.security.auth;

import com.example.security.security.ApplicationUserPermission;
import com.example.security.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@Repository("fakeRepository")
public class FakeApplicationUserDaoService implements ApplicationUserDao{
    private final PasswordEncoder encoder;

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        System.out.println("fakeRepository: selectApplicationUserByUsername(" + username + ") getApplicationUsers(): " + getApplicationUsers());
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        return Lists.newArrayList(
            new ApplicationUser(
                    ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                    encoder.encode("rex"), "rex",
                    true,
                    true,
                    true,
                    true),

                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        encoder.encode("password"), "roxana",
                        true,
                        true,
                        true,
                        true),

                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        encoder.encode("password"), "tom",
                        true,
                        true,
                        true,
                        true)

        );
    }

 /*   List<ApplicationUser> list;
    {
        list = Lists.newArrayList(
                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        encoder.encode("rex"), "rex",
                        true,
                        true,
                        true,
                        true),

                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        encoder.encode("roxana"), "password",
                        true,
                        true,
                        true,
                        true),

                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        encoder.encode("tom"), "password",
                        true,
                        true,
                        true,
                        true)

        );
    }*/
}
