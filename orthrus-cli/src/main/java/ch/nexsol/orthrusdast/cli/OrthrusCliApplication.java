package ch.nexsol.orthrusdast.cli;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import picocli.CommandLine;
import picocli.CommandLine.IFactory;

@SpringBootApplication
@ComponentScan(basePackages = "ch.nexsol.orthrusdast")
public class OrthrusCliApplication implements CommandLineRunner {

    private final ScanCommand scanCommand;
    private final IFactory factory;

    public OrthrusCliApplication(ScanCommand scanCommand, IFactory factory) {
        this.scanCommand = scanCommand;
        this.factory = factory;
    }

    public static void main(String[] args) {
        System.setProperty("server.port", "0");
        System.setProperty("spring.main.web-application-type", "none");
        SpringApplication.run(OrthrusCliApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        int exitCode = new CommandLine(scanCommand, factory).execute(args);
        System.exit(exitCode);
    }
}
