package com.app.supabase;

import com.app.supabase.configuration.SupabaseEnv;
import com.app.supabase.entities.User;
import com.app.supabase.request.Credential;
import com.app.supabase.response.AuthenticatedResponse;
import com.app.supabase.response.SupabaseAuthUser;
import com.app.supabase.response.SupabaseUser;
import com.app.supabase.services.SupabaseAuthService;
import com.app.supabase.services.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class SpringSupabaseApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSupabaseApplication.class, args);
    }

}
