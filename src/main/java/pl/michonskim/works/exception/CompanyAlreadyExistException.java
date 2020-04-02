package pl.michonskim.works.exception;

import java.time.LocalDateTime;

public class CompanyAlreadyExistException extends RuntimeException {
    private final LocalDateTime time;


    public CompanyAlreadyExistException(String message) {
        super(message);
        this.time = LocalDateTime.now();
    }

    @Override
    public String toString() {
        return "CompanyNotFoundException{" +
                "message='" + getMessage() + '\'' +
                ", time=" + time +
                '}';
    }
}
