package ch.nexsol.orthrusdast.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.util.unit.DataSize;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class WebFluxConfig implements WebFluxConfigurer {

    @Value("${spring.codec.max-in-memory-size:50MB}")
    private String maxInMemorySize;

    @Override
    public void configureHttpMessageCodecs(ServerCodecConfigurer configurer) {
        int sizeInBytes = (int) DataSize.parse(maxInMemorySize).toBytes();
        configurer.defaultCodecs().maxInMemorySize(sizeInBytes);
    }
}
