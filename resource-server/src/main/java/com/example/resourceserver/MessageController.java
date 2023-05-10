package com.example.resourceserver;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageController {
	@GetMapping("/")
	String message() {
		return "Hello!";
	}
}
