package com.example.springsocial.security;

import org.springframework.stereotype.Service;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;

@Service
public class ClientUserAllowanceService {

    private List<String> allowedUsers= Arrays.asList("tagore.vuyyuru@gmail.com");
    private Map<String, List<String>> allowedUserByClient = Map.of("USER", allowedUsers);

    public boolean isUserAllowed(String client, String username) {
        return allowedUserByClient.getOrDefault(client, emptyList()).contains(username);
    }

}
