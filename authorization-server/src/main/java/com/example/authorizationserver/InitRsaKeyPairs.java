package com.example.authorizationserver;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Component
public class InitRsaKeyPairs implements ApplicationRunner {
	private final RsaKeyPairRepository repository;
	private final String id;
	private final RSAPublicKey publicKey;
	private final RSAPrivateKey privateKey;

	public InitRsaKeyPairs(RsaKeyPairRepository repository,
			@Value("${jwt.key.id}") String id,
			@Value("${jwt.key.public}") RSAPublicKey publicKey,
			@Value("${jwt.key.private}") RSAPrivateKey privateKey) {
		this.repository = repository;
		this.id = id;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	@Override
	public void run(ApplicationArguments args) {
		this.repository.save(new RsaKeyPairRepository.RsaKeyPair(this.id, Instant.now().minus(Duration.ofDays(1)), publicKey, privateKey));
	}

}
