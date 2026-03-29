package com.mudra.bootsecurity;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Collection;
import java.util.List;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;


@SuppressWarnings("deprecation")
@EnableWebSecurity
public class BootSecurityConfig extends WebSecurityConfigurerAdapter {
	
    @Autowired
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	
    	// Create a filter to generate a SAML Metadata file for the Application
        Saml2MetadataFilter filter = new Saml2MetadataFilter(
        		(RelyingPartyRegistrationResolver)new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository),
                new OpenSamlMetadataResolver());

        // No Transformation of Authorities done
        GrantedAuthoritiesMapper authoritiesMapper = (authCol -> authCol);

        // Actual code to extract the Authorities (or roles) from the Assertion
        Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor =  assertion -> {
        	
        	List<SimpleGrantedAuthority> userRoles 
        		= assertion.getAttributeStatements().stream()
    										.map(AttributeStatement::getAttributes)
    										.flatMap(Collection::stream)
    										.filter(attr -> "groups".equalsIgnoreCase(attr.getName()))
    										.map(Attribute::getAttributeValues)
    										.flatMap(Collection::stream)
    										.map(xml -> new SimpleGrantedAuthority("ROLE_" + xml.getDOM().getTextContent()))
    										.toList();
        	return userRoles;
        };

    	
        http
	        .saml2Login()
		        .addObjectPostProcessor(new ObjectPostProcessor<OpenSamlAuthenticationProvider>() {
		            public <P extends OpenSamlAuthenticationProvider> P postProcess(
		                    P samlAuthProvider) {
		            	
		            	// Set the Authorities extractor 
		                samlAuthProvider.setAuthoritiesExtractor(authoritiesExtractor);
		                samlAuthProvider.setAuthoritiesMapper(authoritiesMapper);
		                return samlAuthProvider;
		            }
		        });
        
        http
	        .saml2Logout(withDefaults())
	        .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class)
	        .authorizeRequests()
	        	.mvcMatchers("/", "/favicon.ico", "/carsonline", "/buy/**", "/user").hasAnyRole("cars.user","cars.admin")
	        	.mvcMatchers("/edit/**").hasAnyRole("cars.admin")
	        	.mvcMatchers("/css/**").permitAll()
	        	.anyRequest().denyAll();
 
    }


}
