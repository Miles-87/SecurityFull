package pl.michonskim.works.exception;

import java.time.LocalDateTime;

public class EmployeeAlreadyExistException extends RuntimeException{
    private final String message;
    private final LocalDateTime time;

    public EmployeeAlreadyExistException(String message, LocalDateTime time) {
        this.message = message;
        this.time = time;
    }

    @Override
    public String toString() {
        return "EmployeeAlreadyExistException{" +
                "message='" + message + '\'' +
                ", time=" + time +
                '}';
    }
}
