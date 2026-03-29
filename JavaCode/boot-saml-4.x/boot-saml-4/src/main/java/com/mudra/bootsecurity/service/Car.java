package com.mudra.bootsecurity.service;


public class Car {
	
	private int id;
	private String make; 
	private String model; 
	private String year; 
	private int count;
	private int price; 
	
	public Car(int id, String make, String model, String year, int count, int price) {
		super();
		this.id = id;
		this.make = make;
		this.model = model;
		this.year = year;
		this.count = count;
		this.price = price;
	}

	public int getId() {
		return id;
	}
	
	public void setId(int id) {
		this.id = id;
	}
	
	public String getMake() {
		return make;
	}
	
	public void setMake(String make) {
		this.make = make;
	}
	
	public String getModel() {
		return model;
	}
	
	public void setModel(String model) {
		this.model = model;
	}
	
	public String getYear() {
		return year;
	}
	
	public void setYear(String year) {
		this.year = year;
	}
	
	public int getCount() {
		return count;
	}
	
	public void setCount(int count) {
		this.count = count;
	}
	
	public Car decrementCount() {
		if (this.count > 0) {
			this.count--;
		}
		
		return this;
	}

	public int getPrice() {
		return price;
	}

	public void setPrice(int price) {
		this.price = price;
	}
	

}
