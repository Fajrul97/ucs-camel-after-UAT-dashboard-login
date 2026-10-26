package org.i3mid.services;

import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.jackson.JacksonDataFormat;
import org.i3mid.models.Response;
import org.i3mid.models.UserInput;
import org.i3mid.util.JWTProcessor;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class DeleteUserRoute extends RouteBuilder {

    @Override
    public void configure() {
        from("direct:searchDeleteUserService").logMask()

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

                .removeHeader("Authorization")

                .setHeader("HttpMethod", header("CamelHttpMethod"))
                .setHeader("HttpPath", header("CamelHttpPath"))
                .setHeader("HttpUrl", header("CamelHttpUrl"))
                .setHeader("HttpLocalAddress", header("CamelVertxPlatformHttpLocalAddress"))
                .setHeader("HttpRemoteAddress", header("CamelVertxPlatformHttpRemoteAddress"))

                .removeHeaders("Camel*")

                .log("Received request from method=${header.HttpMethod}, " +
                        "path=${header.HttpPath}, " +
                        "url=${header.HttpUrl}, " +
                        "localAddress=${header.HttpLocalAddress}, " +
                        "remoteAddress=${header.HttpRemoteAddress}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .process(exchange -> {
                    exchange.setProperty("ucsStartTime", System.currentTimeMillis());
                })

                .toD("{{ucs.baseUrl.write}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .unmarshal(new JacksonDataFormat(UserInput.class))

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .choice()
                .when(exchange -> {

                    if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                        return false;
                    }

                    List<String> groups = exchange.getIn()
                            .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getProperties()
                            .getGroups();

                    // Adding list of blocked group
                    List<String> forbiddenStrings = new ArrayList<>();
                    forbiddenStrings.add("Domain Admins");
                    forbiddenStrings.add("Administrators");
                    forbiddenStrings.add("ITSEC");
                    forbiddenStrings.add("IT-SECDP");

                    // Check if any group contains a forbidden string
                    boolean containsForbidden = groups.stream()
                            .anyMatch(group -> forbiddenStrings.stream().anyMatch(group::contains));

                    exchange.setProperty("containsForbidden", Boolean.valueOf(containsForbidden));

                    return !containsForbidden;

                })
                .setBody(exchange -> {

                    String body = exchange.getIn()
                            .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getDn().toString()
                            .replaceAll(",", "%2C");
                    exchange.setProperty("MyBodyProperty", body.toString());
                    return body;

                })
                .to("direct:deleteUserService")

                .when(exchange -> {

                    Boolean containsForbidden = exchange.getProperty("containsForbidden", Boolean.class);

                    return containsForbidden != null;

                })

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(403))
                .setBody(constant(new Response("97", "FORBIDDEN")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .log(("Status response: " +
                        "ucsUrl={{ucs.baseUrl.write}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms"))

                .when(exchange -> {

                    if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                        return true;
                    }
                    return false;

                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .log(("Status response: " +
                        "ucsUrl={{ucs.baseUrl.write}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms"))
                .end()

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        from("direct:deleteUserService")

                .removeHeaders("Camel*")
                .setHeader(Exchange.HTTP_METHOD, constant("DELETE"))
                .setHeader("Accept", constant("application/json"))

                .setHeader("Authorization", simple("{{ucs.basic64}}"))

                .toD("{{ucs.baseUrl.write}}/univention/udm/users/user/" + "${exchangeProperty.MyBodyProperty}")

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .log(("Status response: " +
                        "ucsUrl={{ucs.baseUrl.write}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms"))
                .end()

        ;
    }

}
