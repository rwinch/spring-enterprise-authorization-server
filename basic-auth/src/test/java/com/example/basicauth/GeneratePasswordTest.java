package com.example.basicauth;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

public class GeneratePasswordTest {
	// https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Password_Storage_Cheat_Sheet.md#bcrypt:~:text=The%20work%20factor%20should%20be%20as%20large%20as%20verification%20server%20performance%20will%20allow%2C%20with%20a%20minimum%20of%2010.
	@Test
	void defaultWorkFactor() {
		generateWithWorkfactor(10);
	}

	@Test
	void workFactor15() {
		generateWithWorkfactor(15);
	}

	@Test
	void workFactor14() {
		generateWithWorkfactor(14);
	}

	@Test
	void workFactor13() {
		generateWithWorkfactor(13);
	}

	@Test
	public void all() {
		for (int workfactor = 4; workfactor < 31; workfactor++) {
			generateWithWorkfactor(workfactor);
		}
	}

	void generateWithWorkfactor(int workfactor) {
		PasswordEncoder encoder = passwordEncoder(workfactor);
		long start = System.currentTimeMillis();
		String encoded = encoder.encode("password");
		System.out.println(encoded);
		long stop = System.currentTimeMillis();
		System.out.println("It took " + (stop - start) + "ms for workfactor of " + workfactor);
	}

	DelegatingPasswordEncoder passwordEncoder(int workfactor) {
		BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(workfactor);
		Map<String, PasswordEncoder> passwordEncoders = Map.of("bcrypt", bcrypt);
		return new DelegatingPasswordEncoder("bcrypt", passwordEncoders);
	}

}
