package pl.michonskim.works.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import pl.michonskim.works.service.CompanyService;

@ExtendWith(MockitoExtension.class)
public class CompanyControllerTest {

    @InjectMocks
    CompanyController companyController;

    @Mock
    CompanyService companyService;

    @Test
    public void testAddCompany() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

    }
}
