package ch.hug.orthrusdast.config;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;

/**
 * WebClient configuration for the scan HTTP client.
 */
@Configuration
public class WebClientConfig {

    @Value("${orthrus.http.connect-timeout-ms:5000}")
    private int connectTimeoutMs;

    @Value("${orthrus.http.read-timeout-ms:10000}")
    private int readTimeoutMs;

    @Value("${orthrus.http.ignore-ssl-errors:false}")
    private boolean ignoreSslErrors;

    @Bean
    public WebClient webClient() {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(readTimeoutMs))
                .followRedirect(true);

        if (ignoreSslErrors) {
            httpClient = httpClient.secure(spec -> {
                try {
                    spec.sslContext(SslContextBuilder.forClient()
                            .trustManager(InsecureTrustManagerFactory.INSTANCE)
                            .build());
                } catch (Exception e) {
                    throw new RuntimeException("Failed to configure insecure SSL", e);
                }
            });
        }

        // Allow larger response bodies (up to 16MB)
        ExchangeStrategies strategies = ExchangeStrategies.builder()
                .codecs(config -> config.defaultCodecs().maxInMemorySize(16 * 1024 * 1024))
                .build();

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .exchangeStrategies(strategies)
                .build();
    }
}
