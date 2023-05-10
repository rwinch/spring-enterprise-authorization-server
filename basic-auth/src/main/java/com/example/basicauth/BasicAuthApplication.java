package com.example.basicauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class BasicAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(BasicAuthApplication.class, args);
	}

}
