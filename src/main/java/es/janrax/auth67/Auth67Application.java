package es.janrax.auth67;

import es.janrax.auth67.shared.domain.Role;
import es.janrax.auth67.shared.domain.User;
import es.janrax.auth67.shared.repository.RoleRepository;
import es.janrax.auth67.shared.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class Auth67Application {

	@Value("${application.security.admin.username:admin}")
	private String adminUsername;

	@Value("${application.security.admin.password:admin123}")
	private String adminPassword;

	public static void main(String[] args) {
		SpringApplication.run(Auth67Application.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			RoleRepository roleRepository,
			UserRepository userRepository,
			PasswordEncoder passwordEncoder
	) {
		return args -> {
			if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
				roleRepository.save(Role.builder().name("ROLE_ADMIN").build());
			}
			if (roleRepository.findByName("ROLE_USER").isEmpty()) {
				roleRepository.save(Role.builder().name("ROLE_USER").build());
			}

			if (userRepository.findByUsername(adminUsername).isEmpty()) {
				Role adminRole = roleRepository.findByName("ROLE_ADMIN").orElseThrow();
				Set<Role> roles = new HashSet<>();
				roles.add(adminRole);

				var admin = User.builder()
						.username(adminUsername)
						.password(passwordEncoder.encode(adminPassword))
						.roles(roles)
						.build();
				userRepository.save(admin);
				System.out.println("Admin user created: " + adminUsername);
			}
		};
	}
}
