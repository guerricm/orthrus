package ch.nexsol.orthrusdast.web;

/**
 * Small helpers shared by the UI controllers.
 */
final class WebFormUtils {

	private WebFormUtils() {
	}

	static int parseIntOrDefault(String value, int defaultValue) {
		if (value == null || value.isBlank()) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(value.trim());
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

}
