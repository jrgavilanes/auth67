package es.janrax.auth67.admin.api;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestRoleController {

    @GetMapping("/special")
    @PreAuthorize("hasRole('SPECIAL_USER')")
    public ResponseEntity<String> onlyForSpecialUser() {
        return ResponseEntity.ok("Bienvenido, usuario con rol SPECIAL_USER. Tienes acceso permitido.");
    }
}
