package com.mudra.bootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/*
 * Change : With Spring Boot 3.x and 4.x 
 * - We don't need to extend WebSecurityConfigurerAdapter anymore. We now use a
 *   @Bean to return a SecurityFilterChain
 * - Some methods in HttpSecurity has been deprecated. The new methods has configurers
 *   as a parameter
 */

@Configuration
public class BootSecurityConfig {
	

	@Bean
	public UserDetailsService userDetailsService() {
		var userDetailsService = new InMemoryUserDetailsManager();

		var user1 = User.withUsername("alice")
						.password("alice")
						.roles("cars.user")
						.build();

		var user2 = User.withUsername("bob")
						.password("bob")
						.roles("cars.admin")
						.build();

		userDetailsService.createUser(user1);
		userDetailsService.createUser(user2);

		return userDetailsService;
	}

	// NoOpPasswordEncoder is just for test. Do not use in Production
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	// change : Return a Spring Bean SecurityFilterChain
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		// setup form
		http.formLogin(configurer -> configurer.defaultSuccessUrl("/carsonline",true))
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/", "/carsonline", "/buy/**", "/user").hasAnyRole("cars.user","cars.admin")
					.requestMatchers("/edit/**").hasAnyRole("cars.admin")
					.anyRequest().authenticated());
		
		// change : return the SecurityFilterChain
		return http.build();
	}

}
