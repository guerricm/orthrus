package ch.hug.orthrusdast;

import ch.hug.orthrusdast.cli.ScanCommand;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import picocli.CommandLine;
import picocli.CommandLine.IFactory;

@SpringBootApplication
public class OrthrusDastSlaveApplication implements CommandLineRunner {

    private final ScanCommand scanCommand;
    private final IFactory factory;
    private final ApplicationContext context;

    public OrthrusDastSlaveApplication(ScanCommand scanCommand, IFactory factory, ApplicationContext context) {
        this.scanCommand = scanCommand;
        this.factory = factory;
        this.context = context;
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            System.setProperty("orthrus.slave.mode", "cli");
            System.setProperty("server.port", "0"); // Bind to random port to avoid conflicts
            System.setProperty("spring.main.web-application-type", "none");
        }
        SpringApplication.run(OrthrusDastSlaveApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        if (args.length > 0) {
            int exitCode = new CommandLine(scanCommand, factory).execute(args);
            System.exit(exitCode);
        }
    }
}
