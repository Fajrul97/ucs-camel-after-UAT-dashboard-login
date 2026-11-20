package org.i3mid.services;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.jackson.JacksonDataFormat;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.i3mid.models.Response;
import org.i3mid.models.UserInput;
import org.i3mid.models.UserVerifyPassword;
import org.i3mid.util.AESEncryptionUtil;
import org.i3mid.util.JWTProcessor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.runtime.util.StringUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class VerifyPasswordRoute extends RouteBuilder {

    @ConfigProperty(name = "secretKey.cbc")
    String cbc;

    @ConfigProperty(name = "secretKey.gcm")
    String gcm;

    @Inject
    UserCacheService userCacheService;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void configure() {
        from("direct:searchVerifyPasswordService").logMask()

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

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))
                .setHeader("Authorization", simple("{{ucs.basic64}}"))

                .process(exchange -> {
                    exchange.setProperty("ucsStartTime", System.currentTimeMillis());
                    String uid = exchange.getIn().getHeader("id", String.class);
                    UserInput cached = userCacheService.getUser(uid);
                    if (cached != null) {
                        exchange.setProperty("cachedUser", cached);
                    }
                })

                .choice()
                .when(exchange -> exchange.getProperty("cachedUser") != null)
                // .log("Cache HIT for uid=${header.id}")
                .process(exchange -> {
                    exchange.getIn().setBody(exchange.getProperty("cachedUser", UserInput.class));
                })
                .otherwise()
                // .log("Cache MISS for uid=${header.id}, fetching from UCS")
                .toD("{{ucs.baseUrl.read}}/univention/udm/users/user/?query[uid]=${header.id}")

                .removeHeader("Authorization")

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .process(exchange -> {
                    String uid = exchange.getIn().getHeader("id", String.class);
                    UserInput userInput = exchange.getIn().getBody(UserInput.class);
                    if (userInput != null && userInput.getResults() > 0) {
                        userCacheService.putUser(uid, userInput); // Store actual data in cache
                    }
                })
                .end()

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .choice()
                .when(exchange -> {

                    if (exchange.getIn().getBody(UserInput.class).getResults() == 1) {
                        return true;
                    }
                    return false;

                })
                .setBody(exchange -> {
                    try {
                        exchange.setProperty("MyBodyProperty", exchange.getIn().getHeader("id", String.class));

                        String username = exchange.getIn().getBody(UserInput.class).get_embedded().getUdmobject().get(0)
                                .getProperties().getUsername();
                        String encryptedPassword = exchange.getIn().getHeader("password", String.class).replaceAll(" ",
                                "+");
                        String version = exchange.getIn().getHeader("X-ENCRYPT-VERSION", String.class);

                        if (StringUtil.isNullOrEmpty(encryptedPassword)) {
                            throw new IllegalArgumentException();
                        }

                        // Decryption process
                        String password;

                        try {
                            if ("v0.2".equalsIgnoreCase(version)) {
                                password = new String(AESEncryptionUtil.decryptGCM(gcm.getBytes(StandardCharsets.UTF_8),
                                        encryptedPassword));
                            } else {
                                password = new String(AESEncryptionUtil.decryptCBC(cbc.getBytes(StandardCharsets.UTF_8),
                                        encryptedPassword));
                            }
                            exchange.setProperty("password", password);
                        } catch (ProviderException e) {
                            if (e.getCause() instanceof ShortBufferException) {
                                throw new IllegalArgumentException();
                            }
                        }

                        exchange.setProperty("username", username);

                        return new UserVerifyPassword(username);

                    } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                            | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                            | NullPointerException e) {

                        throw new IllegalArgumentException();
                    }
                })
                .marshal().json()

                .to("direct:verifyPasswordService")
                .when(exchange -> {

                    if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                        return true;
                    }
                    return false;

                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .marshal().json()

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.read}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms")

                .end()

                .onException(IllegalArgumentException.class)

                .process(exchange -> {

                    Long start = exchange.getProperty("ucsStartTime", Long.class);

                    if (start != null) {
                        long latency = System.currentTimeMillis() - start;
                        exchange.setProperty("ucsLatency", latency);
                    }
                })

                .handled(true)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("96", "INVALID PASSWORD/ENCRYPTION ALGORITHM")))
                .marshal().json()

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.read}}, " +
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

        from("direct:verifyPasswordService")
                .removeHeaders("Camel*")
                .setHeader(Exchange.HTTP_METHOD, constant("POST"))
                .setHeader("Content-Type", constant("application/x-www-form-urlencoded"))
                .setBody(exchange -> {
                    try {
                        String username = exchange.getProperty("username", String.class);
                        String password = exchange.getProperty("password", String.class);
                        return "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                                + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);
                    } finally {
                        exchange.removeProperty("password");
                        exchange.getIn().removeHeader("password");
                    }

                })

                .toD("{{ucs.baseUrl.read}}/univention/auth")

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

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.read}}, " +
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

                .handled(true)
                .process(exchange -> {
                    HttpOperationFailedException cause = exchange.getProperty(Exchange.EXCEPTION_CAUGHT,
                            HttpOperationFailedException.class);
                    String responseBody = cause.getResponseBody();

                    // Parse JSON body
                    ObjectMapper mapper = objectMapper;
                    JsonNode json = mapper.readTree(responseBody);

                    String message = json.path("message").asText();
                    boolean passwordExpired = json.path("result").path("password_expired").asBoolean(false);

                    if (passwordExpired) {
                        // New user or password expired
                        exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 401);
                        exchange.getIn().setBody(new Response("94", "MUST CHANGE PASSWORD AFTER CREATE USER"));
                    } else {
                        // Wrong password or user not found
                        exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 401);
                        exchange.getIn().setBody(new Response("96", "INVALID PASSWORD/ENCRYPTION ALGORITHM"));
                    }
                })
                .marshal().json()

                .log("[${exchangeId}] ${exchangeProperty.reqInfo} | response=${body} | " +
                        "ucsUrl={{ucs.baseUrl.read}}, " +
                        "responseCode=${header.CamelHttpResponseCode}, " +
                        "latency=${exchangeProperty.ucsLatency} ms")

                .end()

        ;

    }

}
