package com.demo_security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.demo_security.jwt.AuthEntryPointJwt;
import com.demo_security.jwt.AuthTokenFilter;
import javax.sql.DataSource;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
    
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
        		.requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/signin", "/profile").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated());
        
        http.sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin())
        );
        
        http.csrf(csrf -> csrf.disable());
        
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    
    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
        	
        	JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
        	JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        	if(!manager.userExists("user")) {
        		UserDetails user = User.withUsername("user")
                        .password(passwordEncoder().encode("demo@123"))
                        .roles("USER")
                        .build();
        		userDetailsManager.createUser(user);
        	}
        	if(!manager.userExists("user")) {
        		UserDetails admin = User.withUsername("admin")
                        .password(passwordEncoder().encode("demo@123"))
                        .roles("ADMIN")
                        .build();
        		userDetailsManager.createUser(admin);
        	} 
        };
    }
    
}