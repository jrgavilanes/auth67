package es.janrax.auth67;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.janrax.auth67.auth.dto.AuthenticationResponse;
import es.janrax.auth67.auth.dto.LoginRequest;
import es.janrax.auth67.auth.dto.RegisterRequest;
import es.janrax.auth67.admin.dto.UserUpdateRequest;
import es.janrax.auth67.shared.domain.Role;
import es.janrax.auth67.shared.domain.User;
import es.janrax.auth67.shared.repository.RoleRepository;
import es.janrax.auth67.shared.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.datasource.url=jdbc:sqlite:auth67-test.db")
public class UserManagementIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String adminToken;

    @BeforeEach
    public void setUp() throws Exception {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        // Create Roles
        Role adminRole = roleRepository.save(Role.builder().name("ROLE_ADMIN").build());
        roleRepository.save(Role.builder().name("ROLE_USER").build());

        // Create Admin User
        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);
        User admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .roles(roles)
                .build();
        userRepository.save(admin);

        // Get Admin Token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("admin")
                .password("admin123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        AuthenticationResponse response = objectMapper.readValue(responseContent, AuthenticationResponse.class);
        adminToken = response.getAccessToken();
    }

    @Test
    public void shouldListUsersAsAdmin() throws Exception {
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1))) // Only admin exists
                .andExpect(jsonPath("$[0].username").value("admin"));
    }

    @Test
    public void shouldUpdateUserAsAdmin() throws Exception {
        // Create another user
        Role userRole = roleRepository.findByName("ROLE_USER").orElseThrow();
        User user = User.builder()
                .username("regular_user")
                .password(passwordEncoder.encode("pass"))
                .roles(Collections.singleton(userRole))
                .build();
        user = userRepository.save(user);

        UserUpdateRequest updateRequest = UserUpdateRequest.builder()
                .locked(true)
                .roles(Collections.singleton("ROLE_MANAGER")) // New role
                .build();

        mockMvc.perform(put("/api/users/" + user.getId())
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.locked").value(true))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_MANAGER"));
    }

    @Test
    public void shouldDeleteUserAsAdmin() throws Exception {
        // Create another user
        Role userRole = roleRepository.findByName("ROLE_USER").orElseThrow();
        User user = User.builder()
                .username("user_to_delete")
                .password(passwordEncoder.encode("pass"))
                .roles(Collections.singleton(userRole))
                .build();
        user = userRepository.save(user);

        mockMvc.perform(delete("/api/users/" + user.getId())
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        // Verify deletion
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1))); // Only admin remains
    }

    @Test
    public void shouldDenyAccessToNonAdmin() throws Exception {
        // Create and login as regular user
        Role userRole = roleRepository.findByName("ROLE_USER").orElseThrow();
        User user = User.builder()
                .username("regular_user")
                .password(passwordEncoder.encode("pass"))
                .roles(Collections.singleton(userRole))
                .build();
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .username("regular_user")
                .password("pass")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String userToken = objectMapper.readValue(result.getResponse().getContentAsString(), AuthenticationResponse.class).getAccessToken();

        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }
}
