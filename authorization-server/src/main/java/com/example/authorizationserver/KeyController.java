package com.example.authorizationserver;

import com.example.authorizationserver.RsaKeyPairRepository.RsaKeyPair;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

@RestController
public class KeyController {
	private final RsaKeyPairRepository repository;

	public KeyController(RsaKeyPairRepository repository) {
		this.repository = repository;
	}


	@PostMapping("/oauth2/jwks")
	String generate() {
		RsaKeyPair keypair = generateKeyPair(Instant.now());
		this.repository.save(keypair);
		return keypair.getId();
	}

	private static RsaKeyPair generateKeyPair(Instant created) {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RsaKeyPair(created, publicKey, privateKey);
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}
