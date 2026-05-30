package ch.hug.vulnapi;

import ch.hug.vulnapi.cli.ScanCommand;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import picocli.CommandLine;
import picocli.CommandLine.IFactory;

@SpringBootApplication
public class OrthrusApplication implements CommandLineRunner {

    private final ScanCommand scanCommand;
    private final IFactory factory;

    public OrthrusApplication(ScanCommand scanCommand, IFactory factory) {
        this.scanCommand = scanCommand;
        this.factory = factory;
    }

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(OrthrusApplication.class);
        if (args.length > 0) {
            System.setProperty("spring.main.web-application-type", "none");
            app.setWebApplicationType(org.springframework.boot.WebApplicationType.NONE);
        }

        org.springframework.context.ApplicationContext context = app.run(args);

        // If we ran a CLI command, system will have exited in run(). If not, we don't
        // exit here.
        if (args.length > 0) {
            int exitCode = SpringApplication.exit(context);
            System.exit(exitCode);
        }
    }

    @Override
    public void run(String... args) throws Exception {
        // If args are provided, we run as CLI. If not, the WebFlux server just starts.
        if (args.length > 0) {
            int exitCode = new CommandLine(scanCommand, factory).execute(args);
            // Optionally shut down the app after CLI execution if we don't want the server
            // to stay alive
            // For now, if we pass args, we assume it's a batch job and exit
            System.exit(exitCode);
        } else {
            System.out.println("Orthrus VulnAPI REST API started. Use CLI arguments to run a scan directly.");
        }
    }
}
