package pl.michonskim.works.exception;

import java.time.LocalDateTime;

public class CompanyNotFoundException extends RuntimeException{
    private final String message;
    private final LocalDateTime time;


    public CompanyNotFoundException(String message,LocalDateTime time) {
        this.message = message;
        this.time = time;
    }

    @Override
    public String toString() {
        return "CompanyNotFoundException{" +
                "message='" + message + '\'' +
                ", time=" + time +
                '}';
    }
}
