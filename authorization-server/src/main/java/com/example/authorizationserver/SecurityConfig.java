package com.example.authorizationserver;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

// https://docs.spring.io/spring-security/reference/servlet/architecture.html
@Configuration
public class SecurityConfig {


	// https://docs.spring.io/spring-authorization-server/docs/1.1.0-SNAPSHOT/reference/html/getting-started.html#defining-required-components
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests(authz -> authz
				.requestMatchers(HttpMethod.POST, "/oauth2/jwks").hasAuthority("SCOPE_keys.write")
			);
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		OAuth2AuthorizationServerConfigurer authz = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
		authz
				.authorizationEndpoint(endpoint -> endpoint
					.consentPage("/oauth2/consent")
				)
				.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0'

		http.securityMatchers(matchers -> matchers
			.requestMatchers(antMatcher("/oauth2/**"), authz.getEndpointsMatcher())
		);
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
					.authenticationEntryPoint(
							new LoginUrlAuthenticationEntryPoint("/login"))
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));

		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/login", "/error").permitAll()
				.anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(login -> login
				.loginPage("/login")
			);

		return http.build();
	}

	@Bean
	JdbcRegisteredClientRepository registeredClientRepository(DataSource dataSource) {
		return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
	}

	@Bean
	JdbcOAuth2AuthorizationConsentService consentService(DataSource dataSource, RegisteredClientRepository clientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(new JdbcTemplate(dataSource), clientRepository);
	}

	@Bean
	JdbcOAuth2AuthorizationService authorizationService(DataSource dataSource, RegisteredClientRepository clientRepository) {
		return new JdbcOAuth2AuthorizationService(new JdbcTemplate(dataSource), clientRepository);
	}

	@Bean
	NimbusJwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}

	@Bean
	JwtGenerator jwtGenerator(JwtEncoder jwtEncoder, OAuth2TokenCustomizer<JwtEncodingContext>  customizer) {
		JwtGenerator generator = new JwtGenerator(jwtEncoder);
		generator.setJwtCustomizer(customizer);
		return generator;
	}
}
