package es.janrax.auth67;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.janrax.auth67.dto.AuthenticationResponse;
import es.janrax.auth67.dto.RefreshTokenRequest;
import es.janrax.auth67.model.Role;
import es.janrax.auth67.model.User;
import es.janrax.auth67.repository.RoleRepository;
import es.janrax.auth67.repository.UserRepository;
import es.janrax.auth67.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class RefreshTokenEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();
    }

    @Test
    void shouldRotateTokensSuccessfully() throws Exception {
        // 1. Setup User and Roles
        Role role = roleRepository.save(Role.builder().name("ROLE_USER").build());
        User user = User.builder()
                .username("testuser")
                .password(passwordEncoder.encode("password"))
                .roles(Collections.singleton(role))
                .locked(false)
                .build();
        // Save first to get ID/Defaults
        user = userRepository.save(user);

        // 2. Generate Initial Tokens
        String initialAccessToken = jwtService.generateToken(user);
        String initialRefreshToken = jwtService.generateRefreshToken(user);

        // 3. Simulate Login: Save RefreshToken to DB
        user.setRefreshToken(initialRefreshToken);
        userRepository.save(user);

        // Ensure token rotation generates a DIFFERENT token (iat change)
        Thread.sleep(1000); 

        // 4. Prepare Request
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken(initialAccessToken);
        request.setRefreshToken(initialRefreshToken);

        // 5. Perform Request
        MvcResult result = mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        // 6. Verify Response
        String responseContent = result.getResponse().getContentAsString();
        AuthenticationResponse response = objectMapper.readValue(responseContent, AuthenticationResponse.class);

        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertNotEquals(initialAccessToken, response.getAccessToken());
        assertNotEquals(initialRefreshToken, response.getRefreshToken());

        // 7. Verify DB Update (Rotation)
        // Fetch fresh user from DB
        User updatedUser = userRepository.findById(user.getId()).orElseThrow();
        assertEquals(response.getRefreshToken(), updatedUser.getRefreshToken());
        assertNotEquals(initialRefreshToken, updatedUser.getRefreshToken());
    }

    @Test
    void shouldFailIfRefreshTokenDoesNotMatchDB_ReusedTokenAttack() throws Exception {
        // 1. Setup User
        Role role = roleRepository.save(Role.builder().name("ROLE_USER").build());
        User user = User.builder()
                .username("victim")
                .password(passwordEncoder.encode("password"))
                .roles(Collections.singleton(role))
                .locked(false)
                .build();
        user = userRepository.save(user);

        // 2. Generate Tokens
        String accessToken = jwtService.generateToken(user);
        String currentRefreshToken = jwtService.generateRefreshToken(user);
        String oldStolenRefreshToken = jwtService.generateRefreshToken(user) + "old"; // Different string

        // 3. Save CURRENT token to DB
        user.setRefreshToken(currentRefreshToken);
        userRepository.save(user);

        // 4. Attacker tries to use OLD token
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken(accessToken);
        request.setRefreshToken(oldStolenRefreshToken);

        // 5. Expect Forbidden
        mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
                
        // 6. Verify DB token was NOT changed (Attacker failed)
        User storedUser = userRepository.findById(user.getId()).orElseThrow();
        assertEquals(currentRefreshToken, storedUser.getRefreshToken());
    }

    @Test
    void shouldFailIfAccessTokenIsInvalid() throws Exception {
        // 1. Setup User
        Role role = roleRepository.save(Role.builder().name("ROLE_USER").build());
        User user = User.builder()
                .username("hacker")
                .password(passwordEncoder.encode("password"))
                .roles(Collections.singleton(role))
                .locked(false)
                .build();
        userRepository.save(user);

        // 2. Prepare Request with Garbage Access Token
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken("invalid.jwt.token");
        request.setRefreshToken("some.refresh.token");

        // 3. Expect Forbidden (Cannot extract username)
        mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }
}