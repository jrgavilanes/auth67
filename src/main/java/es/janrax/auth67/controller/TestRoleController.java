package es.janrax.auth67.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestRoleController {

    @GetMapping("/joputa")
    @PreAuthorize("hasRole('JOPUTA')")
    public ResponseEntity<String> onlyForJoputa() {
        return ResponseEntity.ok("Bienvenido, usuario con rol JOPUTA. Tienes acceso permitido.");
    }
}
