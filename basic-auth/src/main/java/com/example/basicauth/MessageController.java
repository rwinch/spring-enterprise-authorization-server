package com.example.basicauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class MessageController {
	@GetMapping("/**")
	String hello(Principal user) {
		return "Hello '" + user.getName() + "' !";
	}
}
