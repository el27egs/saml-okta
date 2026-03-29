package com.mudra.bootsecurity;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Collection;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider.ResponseAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/*
 * Change : With Spring Boot 4 and Spring Security 7
 * - With 3.x/4.x We don't need to extend WebSecurityConfigurerAdapter anymore. We now use a
 *   @Bean to return a SecurityFilterChain
 * - Some methods in HttpSecurity have been deprecated. 
 * 		- The new methods have configurers as a parameter
 * - pom.xml changes for Spring Boot 4
 * 		- Added "spring-boot-starter-security-saml2" dependency in pom.xml
 * 		- Removed OpenSaml 4 dependencies. OpenSaml 5 is taken automatically
 */
@Configuration
@EnableWebSecurity
public class BootSecurityConfig {
	
	// change : Return a Spring Bean SecurityFilterChain
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		// Change : Using Saml5 libraries
        OpenSaml5AuthenticationProvider authenticationProvider = new OpenSaml5AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(this.authenticationConverter());

		http.authorizeHttpRequests(authorize -> 
				authorize
					.requestMatchers("/", "/carsonline", "/buy/**", "/user").hasAnyRole("cars.user","cars.admin")
					.requestMatchers("/edit/**").hasAnyRole("cars.admin")
					.anyRequest().authenticated())		
			.authenticationManager(new ProviderManager(authenticationProvider))
			.saml2Login(withDefaults())
			.saml2Logout(withDefaults())
			.saml2Metadata(withDefaults()); // Automatically generates metadata url for SP
 
		// change : return the SecurityFilterChain
		return http.build();
	}

	private ResponseAuthenticationConverter authenticationConverter() {
		ResponseAuthenticationConverter authenticationConverter = new ResponseAuthenticationConverter();
		authenticationConverter.setGrantedAuthoritiesConverter((assertion) -> {
			System.out.println(">>>> Convertor called ...");
			return assertion.getAttributeStatements().stream()
					.map(AttributeStatement::getAttributes)
					.flatMap(Collection::stream)
					.filter(attr -> "groups".equalsIgnoreCase(attr.getName()))
					.map(Attribute::getAttributeValues)
					.flatMap(Collection::stream)
					.map(xml -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + xml.getDOM().getTextContent()))
					.toList();
		});
		
		return authenticationConverter;
	}
}
