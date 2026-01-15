package es.janrax.auth67.auth.service;

import es.janrax.auth67.auth.dto.AuthenticationResponse;
import es.janrax.auth67.auth.dto.LoginRequest;
import es.janrax.auth67.auth.dto.RegisterRequest;
import es.janrax.auth67.auth.dto.RefreshTokenRequest;
import es.janrax.auth67.shared.domain.Role;
import es.janrax.auth67.shared.domain.User;
import es.janrax.auth67.shared.repository.RoleRepository;
import es.janrax.auth67.shared.repository.UserRepository;
import es.janrax.auth67.auth.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        Set<Role> roles = new HashSet<>();
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            for (String roleName : request.getRoles()) {
                Role role = roleRepository.findByName(roleName)
                        .orElseGet(() -> roleRepository.save(Role.builder().name(roleName).build()));
                roles.add(role);
            }
        } else {
             Role userRole = roleRepository.findByName("ROLE_USER")
                     .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_USER").build()));
             roles.add(userRole);
        }

        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(roles)
                .locked(false)
                .build();
        // Do not save yet, we need to generate tokens first but tokens need user...
        // Actually, token generation needs UserDetails. The user object is enough.
        
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        String accessToken = request.getAccessToken();
        
        // 1. Extract username from the expired access token to identify the user
        String username = jwtService.extractUsernameIgnoringExpiration(accessToken);
        if (username == null) {
             throw new RuntimeException("Invalid access token");
        }

        // 2. Load user from DB
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        // 3. Validate that the provided Refresh Token matches the one in DB (Single Session / Rotation Check)
        if (user.getRefreshToken() == null || !user.getRefreshToken().equals(refreshToken)) {
            // Potential reuse attack or logged out elsewhere
            throw new RuntimeException("Invalid refresh token");
        }

        // 4. Validate Refresh Token signature and expiration
        if (jwtService.isTokenValid(refreshToken, user)) {
            // 5. Generate NEW tokens (Rotation)
            var newAccessToken = jwtService.generateToken(user);
            var newRefreshToken = jwtService.generateRefreshToken(user);
            
            // 6. Update DB with new Refresh Token
            user.setRefreshToken(newRefreshToken);
            userRepository.save(user);
            
            return AuthenticationResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .build();
        }
        
        throw new RuntimeException("Invalid refresh token");
    }
}
