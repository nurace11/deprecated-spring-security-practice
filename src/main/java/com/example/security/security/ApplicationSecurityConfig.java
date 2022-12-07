package com.example.security.security;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.security.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder encoder;

    // Permission based authentication

    // AntMatchers Whitelist some urls
    // Role based authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails rex = User.builder()
                .username("rex")
                .password(encoder.encode("rex"))
                .roles(STUDENT.name())
                .build();

        UserDetails roxana = User.builder()
                .username("roxana")
                .password(encoder.encode("password"))
                .roles(ADMIN.name())
                .build();

        UserDetails tom = User.builder()
                .username("tom")
                .password(encoder.encode("password"))
                .roles(MODERATOR.name())
                .build();



        return new InMemoryUserDetailsManager(
                rex,
                roxana,
                tom
        );
    }

/*    @Override
    @Bean
    protected UserDetailsService userDetailsService() { // How we retrieve our users from DB
        UserDetails rex = User.builder()
                .username("rex")
                .password(encoder.encode("rex"))
                .roles("STUDENT") // ROLE_STUDENT
                .build();

        UserDetails roxana = User.builder()
                .username("roxana")
                .password(encoder.encode("password"))
                .roles("ADMIN")
                .build();



        return new InMemoryUserDetailsManager(rex);
    }*/

    /*    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // BASIC AUTH
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated() // any request must be authenticated
                .and()
                .httpBasic(); // basic authentication
    }*/
}
