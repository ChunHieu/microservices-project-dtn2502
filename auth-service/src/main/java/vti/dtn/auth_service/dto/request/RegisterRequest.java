package vti.dtn.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RegisterRequest {
    @NotBlank(message = "User must not be blank")
    private String username;

    private String firstName;
    private String lastName;

    @Email(message = "Malformed email")
    @NotBlank(message = "Email must not be blank")
    private String email;

    @NotBlank(message = "Password must not be blank")
    private String password;

    @NotBlank(message = "Role must not be blank")
    @Pattern(regexp = "ADMIN|MANEGER|USER", message = "the role must be ADMIN, MANAGER or USER")
    private String role;
}
