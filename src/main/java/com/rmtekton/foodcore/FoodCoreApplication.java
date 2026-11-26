package com.rmtekton.foodcore;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class FoodCoreApplication {

	public static void main(String[] args) {
		SpringApplication.run(FoodCoreApplication.class, args);
	}
}