package co.edu.uptc.TallerShiro;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.mock.web.MockHttpSession;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void loginSessionAccessLogoutFlow() throws Exception {
        // Perform login (user1/password123 exists in DataInitializer)
        MvcResult login = mockMvc.perform(post("/login")
                .param("username", "user1")
                .param("password", "password123"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("/products/**"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // Access protected page with same session
        mockMvc.perform(get("/products/list").session(session))
                .andExpect(status().isOk());

        // Logout
        mockMvc.perform(get("/logout").session(session))
                .andExpect(status().is3xxRedirection());

        // After logout, accessing protected page should redirect to login
        MvcResult after = mockMvc.perform(get("/products/list").session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = after.getResponse().getHeader("Location");
        assertThat(location).contains("/login");
    }
}
