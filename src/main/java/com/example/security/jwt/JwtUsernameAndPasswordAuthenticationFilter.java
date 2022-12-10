package com.example.security.jwt;



import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Date;
import java.time.LocalDate;

//  jwt - JSON Web Token
// + fast, stateless, used across many services
// - compromised secret key, no visibility to logged in users, token can be stolen

// Encoded
//
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
// HEADER - eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
// .
// PAYLOAD - eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
// .
// VERIFY SIGNATURE - SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

// Decoded
//
// HEADER:
// {
//  "alg": "HS256",
//  "typ": "JWT"
// }
// PAYLOAD:
// {
//  "sub": "1234567890",
//  "name": "John Doe",
//  "iat": 1516239022
// }
// VERIFY SIGNATURE:
// HMACSHA256(
//  base64UrlEncode(header) + "." +
//  base64UrlEncode(payload),
//  [your-256-bit-secret] )

// 1. client -> credentials -> server
// 2. server -> validates credentials -> client
// 3. server -> creates and sends token -> client
// 4. client -> sends token for each request -> server
// 5. server validates token

// This class verify credentials
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // 1-2. in HttpServletRequest client sends credentials, AuthenticationManager validates those credentials
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                        HttpServletResponse response) throws AuthenticationException {
        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest
                    = new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), // principal
                    authenticationRequest.getPassword()  // credentials
            );

            // authenticationManager makes sure that the username exists, and if exists, it will check the password is correct or not
            Authentication authenticate = authenticationManager.authenticate(authenticationToken);
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // 3. Create and send token to client
    // This method will be invoked after attemptAuthentication() is successful
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("succestfullAuthentication() authResult.getName(): " + authResult.getName());
        String key = "LongSecureKeyLongSecureKeyLongSecureKeyLongSecureKeyLongSecureKeyLongSecureKey";
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new java.util.Date())
                .setExpiration(Date.valueOf(LocalDate.now().plusWeeks(2)))// this token will last 2 weeks
                .signWith(Keys.hmacShaKeyFor(key.getBytes()))
                .compact();

        // Like basic authorization, but instead of 'Basic' in the Authorization header value, there must be 'Bearer'
        response.addHeader("Authorization", "Bearer " + token );
    }
}
