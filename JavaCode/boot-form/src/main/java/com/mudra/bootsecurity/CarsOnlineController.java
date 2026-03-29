package com.mudra.bootsecurity;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.view.RedirectView;

import com.mudra.bootsecurity.service.Car;
import com.mudra.bootsecurity.service.CarsOnlineService;

@Controller
public class CarsOnlineController {
	
	@Autowired
	CarsOnlineService carsService;

	@GetMapping("/")
	public RedirectView redirectToCars() {
		return new RedirectView("/carsonline");
	}

	@GetMapping("/carsonline")
	public String showUsedCars(Authentication authentication, Model model) {
		
		// Get all cars from the Service
		List<Car> allCars = carsService.listCars();
		
		// Delegate to the View to show the Car listing
		model.addAttribute("name", authentication.getName());
		model.addAttribute("cars", allCars);
		return "carsonline";
	}
	
	@GetMapping("/buy/{id}")
	public String buyCar(Authentication authentication, Model model, @PathVariable(name = "id") int id) {
		
		model.addAttribute("name", authentication.getName());
		
		Car car = null; 
		try {		
			car = carsService.buyCar(id);
		} catch (Exception e) {
			System.out.println("No Car available !");
		}
		
		model.addAttribute("car", car);
		return "buycar";
	}

	@GetMapping("/edit/{id}")
	public String editCar(Authentication authentication, Model model, @PathVariable(name = "id") int id) {
		
		model.addAttribute("name", authentication.getName());
		return "editcar";
	}

	@GetMapping("/user")
	public String showUser() {	
		return "user";
	}
	

}
