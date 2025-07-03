package vti.dtn.auth_service.dto.reponse;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class RegisterResponse {
    private int status;
    private String message;
}
