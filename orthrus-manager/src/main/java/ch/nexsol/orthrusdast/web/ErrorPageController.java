package ch.nexsol.orthrusdast.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller for handling custom error pages.
 */
@Controller
public class ErrorPageController {

	/**
	 * Handles 403 Forbidden errors.
	 * @return the error 403 template name
	 */
	@GetMapping("/error/403")
	public String error403() {
		return "error/403";
	}

	/**
	 * Handles 401 Unauthorized errors.
	 * @return the error 401 template name
	 */
	@GetMapping("/error/401")
	public String error401() {
		return "error/401";
	}

}
