package inntech.mx;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

/**
 * @author Minsait
 *
 */
@SpringBootApplication
public class DHKeyAgreement2 {
    
    public static void main(String[] args) {
		SpringApplication.run(DHKeyAgreement2.class, args);
    }
	
    @Bean
    public RestTemplate getRestTemplate() {
    	return new RestTemplate();
    }
    
    
}