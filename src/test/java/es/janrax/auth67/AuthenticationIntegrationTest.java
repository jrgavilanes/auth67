package es.janrax.auth67;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.janrax.auth67.dto.AuthenticationResponse;
import es.janrax.auth67.dto.LoginRequest;
import es.janrax.auth67.dto.RegisterRequest;
import es.janrax.auth67.dto.RefreshTokenRequest;
import es.janrax.auth67.model.Role;
import es.janrax.auth67.model.User;
import es.janrax.auth67.repository.RoleRepository;
import es.janrax.auth67.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.datasource.url=jdbc:sqlite:auth67-test.db")
public class AuthenticationIntegrationTest {

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

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @BeforeEach
    public void setUp() {
        // Clean database before each test to ensure isolation
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
    }

    private String getAdminToken() throws Exception {
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
        return response.getAccessToken();
    }

    @Test
    public void shouldRegisterUser() throws Exception {
        String adminToken = getAdminToken();

        RegisterRequest request = RegisterRequest.builder()
                .username("testuser_reg")
                .password("password123")
                .roles(Collections.singleton("ROLE_USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists());
    }

    @Test
    public void shouldAuthenticateUser() throws Exception {
        String adminToken = getAdminToken();

        // 1. Register user first (as admin)
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("testuser_auth")
                .password("password123")
                .roles(Collections.singleton("ROLE_USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        // 2. Authenticate
        LoginRequest loginRequest = LoginRequest.builder()
                .username("testuser_auth")
                .password("password123")
                .build();

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists());
    }

    @Test
    public void shouldFailLoginWithWrongPassword() throws Exception {
        String adminToken = getAdminToken();

        // 1. Register user first (as admin)
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("testuser_fail")
                .password("password123")
                .roles(Collections.singleton("ROLE_USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        // 2. Try login with wrong password
        LoginRequest loginRequest = LoginRequest.builder()
                .username("testuser_fail")
                .password("wrongpassword")
                .build();

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized()); // BadCredentialsException -> 401
    }

    @Test
    public void shouldFailRegistrationWithoutAdmin() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .username("hacker")
                .password("password123")
                .roles(Collections.singleton("ROLE_USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    public void shouldFailRegistrationAsRegularUser() throws Exception {
        // 1. Register a regular user (using admin token)
        String adminToken = getAdminToken();
        RegisterRequest registerUserRequest = RegisterRequest.builder()
                .username("regular_user")
                .password("password123")
                .roles(Collections.singleton("ROLE_USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerUserRequest)))
                .andExpect(status().isOk());

        // 2. Login as that regular user to get their USER token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("regular_user")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        AuthenticationResponse authResponse = objectMapper.readValue(responseContent, AuthenticationResponse.class);
        String userToken = authResponse.getAccessToken();

        // 3. Try to register another user using the USER token
        RegisterRequest hackerRequest = RegisterRequest.builder()
                .username("another_user")
                .password("password123")
                .build();

        mockMvc.perform(post("/api/auth/register")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(hackerRequest)))
                .andExpect(status().isForbidden()); // Must be rejected
    }

    @Test
    public void shouldRefreshToken() throws Exception {
        // 1. Login as admin to get tokens
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
        String refreshToken = response.getRefreshToken();
        String accessToken = response.getAccessToken();

        // 2. Refresh token using the refresh token (and authorized access token)
        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(refreshToken)
                .build();

        mockMvc.perform(post("/api/auth/refresh-token")
                .header("Authorization", "Bearer " + accessToken) // Needs auth now
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists());
    }

    @Test
    public void shouldFailWithExpiredToken() throws Exception {
        // Manually create an expired token
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        String expiredToken = Jwts.builder()
                .subject("admin")
                .issuedAt(new Date(System.currentTimeMillis() - 10000)) // 10s ago
                .expiration(new Date(System.currentTimeMillis() - 1000)) // Expired 1s ago
                .signWith(key)
                .compact();

        // Try to access a secured endpoint with expired token
        mockMvc.perform(post("/api/auth/logout") // Any secured endpoint
                .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isForbidden()); // Filter chain should block it
    }

    @Test
    public void shouldFailLoginWhenUserIsLocked() throws Exception {
        String adminToken = getAdminToken();

        // 1. Register a user
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("locked_user")
                .password("password123")
                .roles(Collections.singleton("ROLE_USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        // 2. Lock the user manually
        User user = userRepository.findByUsername("locked_user").orElseThrow();
        user.setLocked(true);
        userRepository.save(user);

        // 3. Try to login
        LoginRequest loginRequest = LoginRequest.builder()
                .username("locked_user")
                .password("password123")
                .build();

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isForbidden()); // LockedException handled by GlobalExceptionHandler
    }
}
