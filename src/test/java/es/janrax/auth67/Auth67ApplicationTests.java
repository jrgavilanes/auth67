package es.janrax.auth67;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = "spring.datasource.url=jdbc:sqlite:auth67-test.db")
class Auth67ApplicationTests {

	@Test
	void contextLoads() {
	}

}
