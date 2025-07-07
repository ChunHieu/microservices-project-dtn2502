package vti.dtn.auth_service.exeption;

import lombok.Getter;
import org.apache.http.HttpStatus;

@Getter
public class ValidationException extends RuntimeException{
    private HttpStatus status;
    private String message;

    public ValidationException(String message){
        super(message);
        this.status = status;
        this.message = message;
    }
}
