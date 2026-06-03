package ch.hug.orthrusdast;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OrthrusDastApplication {

    public static void main(String[] args) {
        SpringApplication.run(OrthrusDastApplication.class, args);
        System.out.println("Orthrus DAST Master started.");
    }
}
