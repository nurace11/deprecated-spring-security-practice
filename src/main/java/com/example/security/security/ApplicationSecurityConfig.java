package com.example.security.security;

import com.example.security.auth.ApplicationUserService;
import com.example.security.jwt.JwtConfig;
import com.example.security.jwt.JwtTokenVerifier;
import com.example.security.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.security.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@AllArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder encoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig config;
    private final SecretKey secretKey;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session won't be stored in DB

                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), config, secretKey)) // the authenticationManager() comes from WebSecurityConfigurationAdapter class, that this class extends
                .addFilterAfter(new JwtTokenVerifier(config, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();

//                .and()
//                .userDetailsService(applicationUserService);
    }

    // DB authentication
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
        auth.userDetailsService(applicationUserService);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(encoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
/*
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
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .usernameParameter("managerUsername") // input name in login.html page. default: username
                .passwordParameter("managerPassword") // default: password

                .and()
                .rememberMe() // 2 weeks by default
                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(28))
                .key("keykekeykekeykeykeykeykek")
                .rememberMeParameter("remember-me") // rememberMe checkbox name in login.html. default: remember-me

                .and()
                .logout()
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");

//                .and()
//                .userDetailsService(applicationUserService);
    }*/

    // form login
    // logout - any HTTP method if csrf is disabled, only POST if enabled
    // use .logoutRequestMatcher for GET methods with disabled csrf
/*    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()

                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .usernameParameter("managerUsername") // input name in login.html page. default: username
                .passwordParameter("managerPassword") // default: password

                .and()
                .rememberMe() // 2 weeks by default
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(28))
                    .key("keykekeykekeykeykeykeykek")
                    .rememberMeParameter("remember-me") // rememberMe checkbox name in login.html. default: remember-me

                .and()
                .logout()
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");

//                .and()
//                .userDetailsService(applicationUserService);
    }*/

    // csrfToken
/*    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }*/

    // Permission based authentication \\
    // AntMatchers Whitelist some urls \\
/*    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()// csrf - Cross Site Request Forgery
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), MODERATOR.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }*/

/*    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails rex = User.builder()
                .username("rex")
                .password(encoder.encode("rex"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails roxana = User.builder()
                .username("roxana")
                .password(encoder.encode("password"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
        System.out.println(roxana.getAuthorities());

        UserDetails tom = User.builder()
                .username("tom")
                .password(encoder.encode("password"))
//                .roles(MODERATOR.name())
                .authorities(MODERATOR.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                rex,
                roxana,
                tom
        );
    }*/

    // Role based authentication \\
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
