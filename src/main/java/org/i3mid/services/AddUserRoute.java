package org.i3mid.services;

import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.i3mid.models.Response;
import org.i3mid.process.CreateUserTemplate;
import org.i3mid.util.JWTProcessor;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class AddUserRoute extends RouteBuilder {

    @Override

    public void configure() {
        from("direct:addUserService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {

                    List<String> userRoles = (List<String>) exchange.getProperty("userRole");

                    // Adding list of blocked roles
                    List<String> allowedRoles = new ArrayList<>();
                    allowedRoles.add("Administrator");

                    // Check if any user have allowed roles
                    boolean containsAllowedRoles = userRoles.stream()
                            .anyMatch(group -> allowedRoles.stream().anyMatch(group::contains));

                    exchange.setProperty("containsAllowedRoles", Boolean.valueOf(containsAllowedRoles));

                    return !containsAllowedRoles;

                })
                .throwException(new AccessDeniedException("This User doesnt have allowed roles"))
                .end()

                .process(new CreateUserTemplate())

                .removeHeader("Authorization")

                .setHeader("HttpMethod", header("CamelHttpMethod"))
                .setHeader("HttpPath", header("CamelHttpPath"))
                .setHeader("HttpUrl", header("CamelHttpUrl"))
                .setHeader("HttpLocalAddress", header("CamelVertxPlatformHttpLocalAddress"))
                .setHeader("HttpRemoteAddress", header("CamelVertxPlatformHttpRemoteAddress"))

                .removeHeaders("Camel*")

                .setHeader(Exchange.HTTP_METHOD, constant("POST"))
                .setHeader("Accept", constant("application/json"))

                .setHeader("Authorization", simple("{{ucs.basic64}}"))

                .marshal().json()

                .process(exchange -> {
                    exchange.setProperty("ucsStartTime", System.currentTimeMillis());
                })

                .toD("{{ucs.baseUrl.write}}/univention/udm/users/user/")

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))

                .setHeader("HttpResponseCode", header("CamelHttpResponseCode"))

                .removeHeaders("Camel*")

                .marshal().json()

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.write}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms")

                .end()

                .onException(HttpOperationFailedException.class)

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(422))
                .setBody(exchange -> {
                    try {
                        HttpOperationFailedException exception = exchange.getProperty(Exchange.EXCEPTION_CAUGHT,
                                HttpOperationFailedException.class);
                        String responseBody = exception.getResponseBody();

                        if (responseBody.contains("it is too simplistic/systematic")
                                || (responseBody.contains("it does not contain enough DIFFERENT characters")) ||
                                (responseBody.contains("is too simple"))) {
                            return new Response("11",
                                    "PASSWORD MUST CONTAIN 1 UPPERCASE, 1 LOWER CASE, 1 SYMBOL,1 NUMBER AND MUST HAVE A CHARACTER OR SYMBOL BETWEEN 5 DIGIT NUMBERS");
                        } else if (responseBody.contains("password is too short")) {
                            return new Response("12", "PASSWORD MUST CONTAIN AT LEAST 8 CHARACTERS");
                        } else if (responseBody.contains("The domain part of the primary mail address")) {
                            return new Response("13", "EMAIL DOMAIN UNIDENTIFIED");
                        } else if (responseBody.contains("The mail address is already in use")) {
                            return new Response("14", "EMAIL ALREADY IN USE");
                        }
                        return new Response("98", "ID ALREADY EXIST/MISSING PARAMETERS");

                    } catch (Exception e) {
                        return new RuntimeException(e);
                    }
                })
                .handled(true)
                .marshal().json()

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.write}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms")

                .end()

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body}")
                .end()

        ;
    }
}
