package com.example.basicauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

@Configuration
public class SecurityConfig {
	@Bean
	DelegatingPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(14);
		Map<String, PasswordEncoder> passwordEncoders = Map.of("bcrypt", bcrypt);
		return new DelegatingPasswordEncoder("bcrypt", passwordEncoders);
	}
}
