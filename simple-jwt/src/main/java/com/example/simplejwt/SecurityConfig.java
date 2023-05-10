package com.example.simplejwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.disable())
			.httpBasic(Customizer.withDefaults())
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
				.accessDeniedHandler(new BearerTokenAccessDeniedHandler())
			);
		// @formatter:on
		return http.build();
	}

	@Bean
	UserDetailsService users() {
		// @formatter:off
		return new InMemoryUserDetailsManager(
				User.withUsername("user")
						.password("{bcrypt}$2a$14$Wn9AXRJupDyo94IhHYmVo.arNBMpTEa7amqa41xJ5V8iyX/Gh24f2")
						.roles("USER")
						.build()
		);
		// @formatter:on
	}

	@Bean
	JwtDecoder jwtDecoder(@Value("${jwt.public.key}") RSAPublicKey publicKey) {
		return NimbusJwtDecoder.withPublicKey(publicKey).build();
	}

	@Bean
	JwtEncoder jwtEncoder(@Value("${jwt.public.key}") RSAPublicKey publicKey,
		@Value("${jwt.private.key}") RSAPrivateKey privateKey) {
		JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
}
