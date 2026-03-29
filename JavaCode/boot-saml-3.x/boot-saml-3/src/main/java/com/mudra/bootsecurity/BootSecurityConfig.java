package com.mudra.bootsecurity;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Collection;
import java.util.List;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;

/*
 * Change : With Spring Boot 3.x and Spring Security 6.x
 * - We don't need to extend WebSecurityConfigurerAdapter anymore. We now use a
 *   @Bean to return a SecurityFilterChain
 * - Some methods in HttpSecurity has been deprecated. The new methods has configurers
 *   as a parameter
 * - Also, Spring Boot SAML integration now uses OpenSAML Version 4 because of which
 *   there are changes to classes being used and hence the pom.xml file now includes
 *   the opensaml Version 4 jar files.
 * - Added singlelogout property in application.yml
 */
@Configuration
public class BootSecurityConfig {
	
	// change : Return a Spring Bean SecurityFilterChain
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		// change : Create a version of SAML Authenticator Provider which will convert the 
		// "groups" claim into Authorities in the SAML 2 Authentication object
		OpenSaml4AuthenticationProvider samlAuthProv = new OpenSaml4AuthenticationProvider();
		samlAuthProv.setResponseAuthenticationConverter((responseToken) -> {
			
			Converter<ResponseToken, Saml2Authentication> authConvertor 
				= OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();
			
			// Make sure the authorities are set in the SAML Authentication
			Saml2Authentication authentication = authConvertor.convert(responseToken);
			Assertion assertion = responseToken.getResponse().getAssertions().get(0);
			AuthenticatedPrincipal principal = (AuthenticatedPrincipal) authentication.getPrincipal();
			
			// Collection<? extends GrantedAuthority> authorities = authoritiesExtractor.convert(assertion);
			List<SimpleGrantedAuthority> authorities 
				= assertion.getAttributeStatements().stream()
										.map(AttributeStatement::getAttributes)
										.flatMap(Collection::stream)
										.filter(attr -> "groups".equalsIgnoreCase(attr.getName()))
										.map(Attribute::getAttributeValues)
										.flatMap(Collection::stream)
										.map(xml -> new SimpleGrantedAuthority("ROLE_" + xml.getDOM().getTextContent()))
										.toList();

			return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
		});		
		
		http
			.saml2Login(withDefaults())
			.saml2Logout(withDefaults())
			.saml2Metadata(withDefaults())
			.authenticationProvider(samlAuthProv) // change : register the new SAML Auth provider
			.authorizeHttpRequests(authorize -> 
				authorize
					.requestMatchers("/", "/carsonline", "/buy/**", "/user").hasAnyRole("cars.user","cars.admin")
					.requestMatchers("/edit/**").hasAnyRole("cars.admin")
					.anyRequest().authenticated());
 
		// change : return the SecurityFilterChain
		return http.build();
	}

}
