package org.i3mid.util;

import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.io.IOException;

public class JWTProcessor implements Processor {


    @Override
    public void process(Exchange exchange) throws Exception {
        String authHeader = exchange.getIn().getHeader("Authorization", String.class);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            // Decode the JWT token
            DecodedJWT jwt = JWT.decode(token);

            String payload = jwt.getPayload();

            byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(payload);
            String decodedPayload = new String(decodedBytes);

            ObjectMapper mapper = new ObjectMapper();
            JsonNode payloadJson = null;
            try {
                payloadJson = mapper.readTree(decodedPayload);
            } catch (IOException e) {
                e.printStackTrace();
            }

            // System.out.println(payloadJson);

            if (payloadJson != null && payloadJson.has("realm_access")) {
            JsonNode realmAccess = payloadJson.get("realm_access");
            if (realmAccess.has("roles")) {
            JsonNode roles = realmAccess.get("roles");
            List<String> rolesList = mapper.convertValue(roles, List.class);

            exchange.setProperty("userRole", rolesList);

            System.out.println("User Roles: " + rolesList);
            } 
            else {
            System.out.println("No roles found in the 'realm_access' claim.");
            }
            } 
            else {
            System.out.println("No 'realm_access' claim found in the token.");
            }
        }
    }
    
}