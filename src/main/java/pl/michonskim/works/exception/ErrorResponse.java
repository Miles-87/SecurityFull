package pl.michonskim.works.exception;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ErrorResponse {
    private String message;
    private LocalDateTime time;

    public ErrorResponse(String message, LocalDateTime time) {
        this.message = message;
        this.time = time;
    }
}
