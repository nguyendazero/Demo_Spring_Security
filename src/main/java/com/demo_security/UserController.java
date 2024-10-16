package com.demo_security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

	@Autowired
	DataSource dataSource;
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping("/public/users")
	public String createUser(@RequestParam String username,
							 @RequestParam String password,
							 @RequestParam String role) {
		JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
		
		if(userDetailsManager.userExists(username)) {
			return "user already exists";
		}
		
		UserDetails user = User.withUsername(username)
				.password(passwordEncoder.encode(password))
				.roles(role)
				.build();
		userDetailsManager.createUser(user);
		return "User created successfully";
	}
	
}
