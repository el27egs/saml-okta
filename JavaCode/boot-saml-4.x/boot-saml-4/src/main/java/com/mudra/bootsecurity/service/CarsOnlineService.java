package com.mudra.bootsecurity.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

//Change : All javax.* changes to jakarta.* with Spring Boot 3
import jakarta.annotation.PostConstruct;

/*
 * Not efficient when it comes to Synchronization
 */
@Service
public class CarsOnlineService {
	
	private int index = 0;
	
	// Cache of all the cars
	private List<Car> cars = new ArrayList<>();
	
	@PostConstruct
	private void initialize() {
		
		// initialize the cache with some used cars
		addCar(new Car(0, "Honda", "Accord", "2017", 17, 15000));
		addCar(new Car(0, "Honda", "Accord", "2020", 20, 20000));
		addCar(new Car(0, "Honda", "Accord", "2018", 18, 17000));
		
		addCar(new Car(0, "Toyota", "Camry", "2018", 10, 18000));
		addCar(new Car(0, "Toyota", "Camry", "2020", 20, 22000));
		
		addCar(new Car(0, "Tesla", "Model S", "2020", 3, 100000));
		addCar(new Car(0, "Tesla", "Model Y", "2021", 10, 50000));
		
	}
	
	/**
	 * Return the list of used cars 
	 * @return
	 */
	public synchronized List<Car> listCars() {
		return new ArrayList<>(cars); 
	}
	
	/**
	 * Add a used car for sale
	 * @param car
	 */
	public synchronized void addCar(Car car) {
		
		this.index++;
		car.setId(this.index);
		cars.add(car);
	}
	
	/**
	 * Return the Car for that Id and reduce count
	 * @param id
	 * @return
	 */
	public synchronized Car buyCar(int id) {
		
		return this.cars.stream()
						.filter(car -> car.getId() == id && car.getCount() > 0)
						.findFirst()
						.orElseThrow()
						.decrementCount();
	}

}
