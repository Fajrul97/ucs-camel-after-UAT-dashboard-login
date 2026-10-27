package org.i3mid.services;

import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.jackson.JacksonDataFormat;
import org.i3mid.exception.ResultMoreThanOneException;
import org.i3mid.exception.ResultNotFoundException;
import org.i3mid.models.Response;
import org.i3mid.models.UserInput;
import org.i3mid.models.UserOutput;
import org.i3mid.util.JWTProcessor;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class SearchUserRoute extends RouteBuilder {

    @Override
    public void configure() {
        from("direct:searchUserService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {

                    List<String> userRoles = (List<String>) exchange.getProperty("userRole");

                    // Adding list of blocked roles
                    List<String> allowedRoles = new ArrayList<>();
                    allowedRoles.add("Administrator");
                    allowedRoles.add("Operations");
                    allowedRoles.add("App-Adm");

                    // Check if any user have allowed roles
                    boolean containsAllowedRoles = userRoles.stream()
                            .anyMatch(group -> allowedRoles.stream().anyMatch(group::contains));

                    exchange.setProperty("containsAllowedRoles", Boolean.valueOf(containsAllowedRoles));

                    return !containsAllowedRoles;
                })

                .throwException(new AccessDeniedException("This User doesnt have allowed roles"))
                .end()

                .removeHeader("Authorization")

                .setHeader("HttpMethod", header("CamelHttpMethod"))
                .setHeader("HttpPath", header("CamelHttpPath"))
                .setHeader("HttpUrl", header("CamelHttpUrl"))
                .setHeader("HttpLocalAddress", header("CamelVertxPlatformHttpLocalAddress"))
                .setHeader("HttpRemoteAddress", header("CamelVertxPlatformHttpRemoteAddress"))

                .removeHeaders("Camel*")

                // .log("Received request from method=${header.HttpMethod}, " +
                // "path=${header.HttpPath}, " +
                // "url=${header.HttpUrl}, " +
                // "localAddress=${header.HttpLocalAddress}, " +
                // "remoteAddress=${header.HttpRemoteAddress}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .process(exchange -> {
                    exchange.setProperty("ucsStartTime", System.currentTimeMillis());
                })

                .toD("{{ucs.baseUrl.read}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .setBody(exchange -> {
                    try {
                        return new UserOutput(exchange.getIn().getBody(UserInput.class));
                    } catch (ResultMoreThanOneException | ResultNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                })
                .marshal().json()

                // .log(("Sending response ${body}"))
                // .log(("Status response: " +
                // "ucsUrl={{ucs.baseUrl.read}}, " +
                // "responseCode=${header.CamelHttpResponseCode}, " +
                // "latency=${exchangeProperty.ucsLatency} ms"))

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.read}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms")

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                // .log(("Sending response ${body}"))
                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body}")
                .end()

                .onException(ResultNotFoundException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .handled(true)
                .marshal().json()
                // .log(("Sending response ${body}"))
                // .log(("Status response: " +
                // "ucsUrl={{ucs.baseUrl.read}}, " +
                // "responseCode=${header.CamelHttpResponseCode}, " +
                // "latency=${exchangeProperty.ucsLatency} ms"))

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.read}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms")

                .end()

        ;

    }

}
