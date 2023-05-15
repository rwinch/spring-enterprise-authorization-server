package com.example.authorizationserver;

import org.springframework.stereotype.Component;

import java.util.*;
@Component
public class InMemoryRsaKeyPairRepository implements RsaKeyPairRepository {

	private final Map<String, RsaKeyPair> idToKeyPair = new HashMap<>();

	@Override
	public List<RsaKeyPair> findKeyPairs() {
		List<RsaKeyPair> result = new ArrayList<>(this.idToKeyPair.values());
		Collections.sort(result, Comparator.comparing(RsaKeyPair::getCreated).reversed());
		return result;
	}

	@Override
	public void delete(String id) {
		this.idToKeyPair.remove(id);
	}

	@Override
	public void save(RsaKeyPair rsaKeyPair) {
		this.idToKeyPair.put(rsaKeyPair.getId(), rsaKeyPair);
	}

}
