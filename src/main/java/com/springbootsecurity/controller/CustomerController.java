package com.springbootsecurity.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.springbootsecurity.model.Customer;

@RestController
public class CustomerController {
	final private List<Customer> customers = List.of(
			Customer.builder().id("001").name("Customer 1").email("c1@gmail.com").build(),
			Customer.builder().id("002").name("Customer 2").email("c2@gmail.com").build()
	);
	
	@GetMapping("/hello")
	public ResponseEntity<String> hello(){
		return ResponseEntity.ok("hello is exeption");
	}
	
	@GetMapping("/customer/{id}")
	public ResponseEntity<Customer> getCustomerList(@PathVariable("id") String id){
		List<Customer> customers = this.customers.stream().filter(customer -> customer.getId().equals(id)).toList();
		return ResponseEntity.ok(customers.get(0));
	}
}
