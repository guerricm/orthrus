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
        // We use exit code from SpringApplication which will include the picocli exit code
        System.exit(SpringApplication.run(OrthrusApplication.class, args).getEnvironment().getProperty("spring.boot.exitcode", Integer.class, 0));
    }

    @Override
    public void run(String... args) throws Exception {
        // If args are provided, we run as CLI. If not, the WebFlux server just starts.
        if (args.length > 0) {
            int exitCode = new CommandLine(scanCommand, factory).execute(args);
            // Optionally shut down the app after CLI execution if we don't want the server to stay alive
            // For now, if we pass args, we assume it's a batch job and exit
            System.exit(exitCode);
        } else {
            System.out.println("Orthrus VulnAPI REST API started. Use CLI arguments to run a scan directly.");
        }
    }
}
