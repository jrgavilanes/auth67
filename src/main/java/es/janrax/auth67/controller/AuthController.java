package es.janrax.auth67.controller;

import es.janrax.auth67.dto.AuthenticationResponse;
import es.janrax.auth67.dto.LoginRequest;
import es.janrax.auth67.dto.RefreshTokenRequest;
import es.janrax.auth67.dto.RegisterRequest;
import es.janrax.auth67.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @Valid @RequestBody LoginRequest request
    ) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken(
            @RequestBody RefreshTokenRequest request
    ) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        // In a stateless JWT architecture, logout is primarily handled by the client
        // deleting the token. Optionally, a blacklist can be implemented server-side.
        return ResponseEntity.ok("Logout successful. Please remove the token from client storage.");
    }
}
