package pl.michonskim.works.exception;

import pl.michonskim.works.entity.User;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
        super(message);
    }
}
