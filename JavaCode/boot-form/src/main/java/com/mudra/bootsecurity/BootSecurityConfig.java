package com.mudra.bootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


@SuppressWarnings("deprecation")
@EnableWebSecurity
public class BootSecurityConfig extends WebSecurityConfigurerAdapter {
	

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
	
	@Bean
	public PasswordEncoder passwordEncoder() {
	  return NoOpPasswordEncoder.getInstance();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// setup form 
		http.formLogin()
				.defaultSuccessUrl("/carsonline",true)
			.and()
			.authorizeRequests()
	        	.mvcMatchers("/", "/favicon.ico", "/carsonline", "/buy/**", "/user").hasAnyRole("cars.user","cars.admin")
	        	.mvcMatchers("/edit/**").hasAnyRole("cars.admin")
	        	.mvcMatchers("/css/**").permitAll()
	        	.anyRequest().denyAll();
	}

}
