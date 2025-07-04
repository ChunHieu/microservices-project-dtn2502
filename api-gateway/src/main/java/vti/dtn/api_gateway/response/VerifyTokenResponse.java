package vti.dtn.api_gateway.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class VerifyTokenResponse {
    private int status;
    private String message;
    private String xUserToken;
}
