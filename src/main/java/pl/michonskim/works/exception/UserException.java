package pl.michonskim.works.exception;

import java.time.LocalDateTime;

public class UserException extends RuntimeException{
    private final String message;
    private final LocalDateTime time;

    public UserException(String message, LocalDateTime time) {
        this.message = message;
        this.time = time;
    }
}
