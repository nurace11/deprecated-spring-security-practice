package com.example.security;

import com.example.security.auth.ApplicationUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(ApplicationUserService service) {
		return args -> {
			System.out.println("Something");
			service.loadUserByUsername("roxana");
		};
	}

}
