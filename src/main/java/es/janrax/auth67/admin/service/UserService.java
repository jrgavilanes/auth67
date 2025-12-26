package es.janrax.auth67.admin.service;

import es.janrax.auth67.admin.dto.UserResponse;
import es.janrax.auth67.admin.dto.UserUpdateRequest;
import es.janrax.auth67.shared.domain.Role;
import es.janrax.auth67.shared.domain.User;
import es.janrax.auth67.shared.repository.RoleRepository;
import es.janrax.auth67.shared.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    public UserResponse updateUser(Long id, UserUpdateRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (request.getLocked() != null) {
            user.setLocked(request.getLocked());
        }

        if (request.getRoles() != null) {
            Set<Role> roles = new HashSet<>();
            for (String roleName : request.getRoles()) {
                 Role role = roleRepository.findByName(roleName)
                         .orElseGet(() -> roleRepository.save(Role.builder().name(roleName).build()));
                 roles.add(role);
            }
            user.setRoles(roles);
        }

        User savedUser = userRepository.save(user);
        return mapToUserResponse(savedUser);
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .locked(user.isLocked()) // Accessing the field directly or via lombok getter if created
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .build();
    }
}
