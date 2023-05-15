package com.example.authorizationserver;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface RsaKeyPairRepository {

	List<RsaKeyPair> findKeyPairs();

	void delete(String id);

	void save(RsaKeyPair rsaKeyPair);

	class RsaKeyPair {

		private final String id;

		private final Instant created;

		private final RSAPublicKey publicKey;

		private final RSAPrivateKey privateKey;

		public RsaKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
			this(UUID.randomUUID().toString(), Instant.now(), publicKey, privateKey);
		}

		public RsaKeyPair(Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
			this(UUID.randomUUID().toString(), created, publicKey, privateKey);
		}

		public RsaKeyPair(String id, Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
			this.id = id;
			this.created = created;
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}

		public String getId() {
			return id;
		}

		public Instant getCreated() {
			return created;
		}

		public RSAPublicKey getPublicKey() {
			return publicKey;
		}

		public RSAPrivateKey getPrivateKey() {
			return privateKey;
		}
	}

}
