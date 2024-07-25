package org.i3mid;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.http.HttpComponent;
import org.apache.camel.component.jackson.JacksonDataFormat;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.apache.camel.model.rest.RestBindingMode;
import org.apache.camel.support.jsse.SSLContextParameters;
import org.apache.camel.support.jsse.TrustManagersParameters;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.i3mid.exception.ResultMoreThanOneException;
import org.i3mid.exception.ResultNotFoundException;
import org.i3mid.models.ChangePasswordRequest;
import org.i3mid.models.Response;
import org.i3mid.models.UserInput;
import org.i3mid.models.UserOutput;
import org.i3mid.models.UserVerifyPassword;
import org.i3mid.process.CreateUserTemplate;
import org.i3mid.util.AESEncryptionUtil;
import org.i3mid.util.JWTProcessor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.netty.util.Constant;
import io.quarkus.security.UnauthorizedException;
import jakarta.enterprise.context.ApplicationScoped;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.nio.file.AccessDeniedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@ApplicationScoped
public class Routes extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        HttpComponent httpComponent = getContext().getComponent("https", HttpComponent.class);
        TrustManagersParameters trustManagersParameters = new TrustManagersParameters();
        X509ExtendedTrustManager extendedTrustManager = new InsecureX509TrustManager();
        trustManagersParameters.setTrustManager(extendedTrustManager);

        SSLContextParameters sslContextParameters = new SSLContextParameters();
        sslContextParameters.setTrustManagers(trustManagersParameters);
        httpComponent.setSslContextParameters(sslContextParameters);
        httpComponent.setX509HostnameVerifier(new AllowAllHostnameVerifier());

        // restConfiguration().bindingMode(RestBindingMode.json);

        from("timer:foo?repeatCount=1")
                .log("JVM Version: ${sys.java.runtime.version}");

        rest("/ldapService")
                .get().to("direct:restService");

        from("direct:restService")
                .choice()
                .when(simple("${header.operation} == 'search'"))
                .to("direct:searchService")
                .when(simple("${header.operation} == 'addUser'"))
                .to("direct:addUserService")
                .when(simple("${header.operation} == 'deleteUser'"))
                .to("direct:searchDeleteUserService")
                .when(simple("${header.operation} == 'changePassword'"))
                .to("direct:searchChangePasswordService")
                .when(simple("${header.operation} == 'resetPassword'"))
                .to("direct:searchResetPasswordService")
                .when(simple("${header.operation} == 'verifyPassword'"))
                .to("direct:searchVerifyPasswordService")
                .endChoice();

        ////////// Search User Service

        from("direct:searchService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {
                    try {

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

                    } finally {
                        // DO nothing
                    }
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
                .log("Received request from ${headers}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .setBody(exchange -> {
                    try {
                        return new UserOutput(exchange.getIn().getBody(UserInput.class));
                    } catch (ResultMoreThanOneException | ResultNotFoundException e) {
                        System.out.println(e.getClass());
                        throw new RuntimeException(e);
                    }
                })
                .marshal().json()
                .log(("Sending response ${body}"))

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(ResultNotFoundException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        ////////////////// Add User Service
        from("direct:addUserService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {
                    try {

                        List<String> userRoles = (List<String>) exchange.getProperty("userRole");

                        // Adding list of blocked roles
                        List<String> allowedRoles = new ArrayList<>();
                        allowedRoles.add("Administrator");

                        // Check if any user have allowed roles
                        boolean containsAllowedRoles = userRoles.stream()
                                .anyMatch(group -> allowedRoles.stream().anyMatch(group::contains));

                        exchange.setProperty("containsAllowedRoles", Boolean.valueOf(containsAllowedRoles));

                        return !containsAllowedRoles;

                    } finally {
                        // DO nothing
                    }
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
                .log("Received request from ${headers}")

                .setHeader(Exchange.HTTP_METHOD, constant("POST"))
                .setHeader("Accept", constant("application/json"))

                .setHeader("Authorization", simple("{{ucs.basic64}}"))

                .marshal().json()

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/")

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))
                .removeHeaders("Camel*")
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                // .onException(HttpOperationFailedException.class)
                // .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(422))
                // .setBody(constant(new Response("98", "ID ALREADY EXIST")))
                // .handled(true)
                // .marshal().json()
                // .log(("Sending response ${body}"))
                // .end()

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(HttpOperationFailedException.class)
                .transform().simple("${exception.message}")
                // .onWhen(${exception.message}.contains("mail"))

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(422))
                // .setBody(constant(new Response("93", "EMAIL IS NOT IN THE LIST OF MAIL
                // DOMAINS")))
  
                .log(("Sending response ${body}"))
                .end()

        ;

        /////////////// Delete User Service
        from("direct:searchDeleteUserService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {
                    try {

                        List<String> userRoles = (List<String>) exchange.getProperty("userRole");

                        // Adding list of blocked roles
                        List<String> allowedRoles = new ArrayList<>();
                        allowedRoles.add("Administrator");

                        // Check if any user have allowed roles
                        boolean containsAllowedRoles = userRoles.stream()
                                .anyMatch(group -> allowedRoles.stream().anyMatch(group::contains));

                        exchange.setProperty("containsAllowedRoles", Boolean.valueOf(containsAllowedRoles));

                        return !containsAllowedRoles;

                    } finally {
                        // DO nothing
                    }
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
                .log("Received request from ${headers}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .choice()
                .when(exchange -> {
                    try {

                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return false;
                        }

                        List<String> groups = exchange.getIn()
                                .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getProperties()
                                .getGroups();

                        // Adding list of blocked group
                        List<String> forbiddenStrings = new ArrayList<>();
                        // forbiddenStrings.add("Computers");
                        forbiddenStrings.add("Domain Admins");
                        forbiddenStrings.add("Administrators");
                        forbiddenStrings.add("ITSEC");
                        forbiddenStrings.add("IT-SECDP");

                        // Check if any group contains a forbidden string
                        boolean containsForbidden = groups.stream()
                                .anyMatch(group -> forbiddenStrings.stream().anyMatch(group::contains));

                        exchange.setProperty("containsForbidden", Boolean.valueOf(containsForbidden));

                        return !containsForbidden;

                    } finally {
                        // DO nothing
                    }
                })
                .setBody(exchange -> {
                    try {
                        String body = exchange.getIn()
                                .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getDn().toString()
                                .replaceAll(",", "%2C");
                        exchange.setProperty("MyBodyProperty", body.toString());
                        return body;
                    } finally {
                        // DO nothing
                    }
                })
                .to("direct:deleteUserService")

                .when(exchange -> {
                    try {

                        Boolean containsForbidden = (Boolean) exchange.getProperty("containsForbidden");

                        return containsForbidden != null;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(403))
                .setBody(constant(new Response("97", "FORBIDDEN")))
                .marshal().json()
                .log(("Sending response ${body}"))

                .when(exchange -> {
                    try {
                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return true;
                        }
                        return false;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .marshal().json()
                .log(("Sending response ${body}"))
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

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/" + "${exchangeProperty.MyBodyProperty}")

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        ///////////// Change Password Service
        from("direct:searchChangePasswordService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {
                    try {

                        List<String> userRoles = (List<String>) exchange.getProperty("userRole");

                        // Adding list of blocked roles
                        List<String> allowedRoles = new ArrayList<>();
                        allowedRoles.add("Administrator");
                        allowedRoles.add("App-Adm");

                        // Check if any user have allowed roles
                        boolean containsAllowedRoles = userRoles.stream()
                                .anyMatch(group -> allowedRoles.stream().anyMatch(group::contains));

                        exchange.setProperty("containsAllowedRoles", Boolean.valueOf(containsAllowedRoles));

                        return !containsAllowedRoles;

                    } finally {
                        // DO nothing
                    }
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
                .log("Received request from ${headers}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .choice()
                .when(exchange -> {
                    try {

                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return false;
                        }

                        List<String> groups = exchange.getIn()
                                .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getProperties()
                                .getGroups();

                        // Adding list of blocked group
                        List<String> forbiddenStrings = new ArrayList<>();
                        // forbiddenStrings.add("Computers");
                        forbiddenStrings.add("Domain Admins");
                        forbiddenStrings.add("Administrators");
                        forbiddenStrings.add("ITSEC");
                        forbiddenStrings.add("IT-SECDP");

                        // Check if any group contains a forbidden string
                        boolean containsForbidden = groups.stream()
                                .anyMatch(group -> forbiddenStrings.stream().anyMatch(group::contains));

                        exchange.setProperty("containsForbidden", Boolean.valueOf(containsForbidden));

                        return !containsForbidden;

                    } finally {
                        // DO nothing
                    }
                })
                .setBody(exchange -> {
                    try {
                        String body = exchange.getIn()
                                .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getDn().toString()
                                .replaceAll(",", "%2C");
                        exchange.setProperty("MyBodyProperty", body.toString());

                        String encryptedPassword = exchange.getIn().getHeader("newPassword", String.class)
                                .replaceAll(" ", "+");

                        // process decryption
                        String password = new String(AESEncryptionUtil
                                .decrypt("9Y@ov#XLt@bNN@We^fqDypo%v5vv$7Ah".getBytes(), encryptedPassword));

                        return new ChangePasswordRequest(exchange.getIn().getBody(UserInput.class), password);

                    } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                            | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                            | IllegalArgumentException e) {

                        return new RuntimeException(e);
                    } finally {
                        // Do nothing
                    }
                })
                .marshal().json()
                .to("direct:changePasswordService")
                .when(exchange -> {
                    try {

                        Boolean containsForbidden = (Boolean) exchange.getProperty("containsForbidden");

                        return containsForbidden != null;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(403))
                .setBody(constant(new Response("97", "FORBIDDEN")))
                .marshal().json()
                .log(("Sending response ${body}"))

                .when(exchange -> {
                    try {
                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return true;
                        }
                        return false;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        from("direct:changePasswordService")
                .removeHeaders("Camel*")
                .setHeader(Exchange.HTTP_METHOD, constant("PUT"))
                .setHeader("Content-Type", constant("application/json"))

                .setHeader("Authorization", simple("{{ucs.basic64}}"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/" + "${exchangeProperty.MyBodyProperty}")

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(HttpOperationFailedException.class)
                .onWhen(exceptionMessage().contains("statusCode: 422"))
                .handled(true)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("96", "INVALID ENCRYPTION ALGORITHM/PASSWORD ALREADY USED")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        ////////////// Reset Password Service
        from("direct:searchResetPasswordService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {
                    try {

                        List<String> userRoles = (List<String>) exchange.getProperty("userRole");

                        // Adding list of blocked roles
                        List<String> allowedRoles = new ArrayList<>();
                        allowedRoles.add("Administrator");

                        // Check if any user have allowed roles
                        boolean containsAllowedRoles = userRoles.stream()
                                .anyMatch(group -> allowedRoles.stream().anyMatch(group::contains));

                        exchange.setProperty("containsAllowedRoles", Boolean.valueOf(containsAllowedRoles));

                        return !containsAllowedRoles;

                    } finally {
                        // DO nothing
                    }
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
                .log("Received request from ${headers}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .choice()
                .when(exchange -> {
                    try {

                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return false;
                        }

                        List<String> groups = exchange.getIn()
                                .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getProperties()
                                .getGroups();

                        // Adding list of blocked group
                        List<String> forbiddenStrings = new ArrayList<>();
                        // forbiddenStrings.add("Computers");
                        forbiddenStrings.add("Domain Admins");
                        forbiddenStrings.add("Administrators");
                        forbiddenStrings.add("ITSEC");
                        forbiddenStrings.add("IT-SECDP");

                        // Check if any group contains a forbidden string
                        boolean containsForbidden = groups.stream()
                                .anyMatch(group -> forbiddenStrings.stream().anyMatch(group::contains));

                        exchange.setProperty("containsForbidden", Boolean.valueOf(containsForbidden));

                        return !containsForbidden;

                    } finally {
                        // DO nothing
                    }
                })
                .setBody(exchange -> {
                    try {

                        String body = exchange.getIn()
                                .getBody(UserInput.class).get_embedded().getUdmobject().get(0).getDn().toString()
                                .replaceAll(",", "%2C");
                        exchange.setProperty("MyBodyProperty", body.toString());

                        return new ChangePasswordRequest(exchange.getIn().getBody(UserInput.class),
                                // exchange.getIn().getBody(UserInput.class).get_embedded().getUdmobject().get(0)
                                // .getProperties().getBirthday().replaceAll("-", ""));
                                "M3ga@123!");

                    } finally {
                        // Do nothing
                    }
                })
                .marshal().json()

                .to("direct:resetPasswordService")

                .when(exchange -> {
                    try {

                        Boolean containsForbidden = (Boolean) exchange.getProperty("containsForbidden");

                        return containsForbidden != null;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(403))
                .setBody(constant(new Response("97", "FORBIDDEN")))
                .marshal().json()
                .log(("Sending response ${body}"))

                .when(exchange -> {
                    try {
                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return true;
                        }
                        return false;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        from("direct:resetPasswordService")

                .removeHeaders("Camel*")
                .setHeader(Exchange.HTTP_METHOD, constant("PUT"))
                .setHeader("Content-Type", constant("application/json"))

                .setHeader("Authorization", constant("{{ucs.basic64}}"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/" + "${exchangeProperty.MyBodyProperty}")

                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(HttpOperationFailedException.class)
                .onWhen(exceptionMessage().contains("statusCode: 422"))
                .handled(true)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(422))
                .setBody(constant(new Response("95", "PASSWORD ALREADY RESET")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        ////////////// Verify Password Service
        from("direct:searchVerifyPasswordService").logMask()

                // Process JWT for RBAC
                .process(new JWTProcessor())

                .choice()
                .when(exchange -> {
                    try {

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

                    } finally {
                        // DO nothing
                    }
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
                .log("Received request from ${headers}")

                .setHeader(Exchange.HTTP_METHOD, constant("GET"))
                .setHeader("Accept", constant("application/json"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/?query[uid]=${header.id}" +
                        "&authUsername={{ucs.username}}" + "&authPassword={{ucs.password}}")

                .unmarshal(new JacksonDataFormat(UserInput.class))
                .choice()
                .when(exchange -> {
                    try {
                        if (exchange.getIn().getBody(UserInput.class).getResults() == 1) {
                            return true;
                        }
                        return false;
                    } finally {
                        // DO nothing
                    }
                })
                .setBody(exchange -> {
                    try {

                        if (exchange.getIn().getBody(UserInput.class).get_embedded().getUdmobject().get(0)
                                .getProperties().getPwdChangeNextLogin()) {
                            throw new UnauthorizedException();

                        }

                        exchange.setProperty("MyBodyProperty", exchange.getIn().getHeader("id", String.class));

                        String username = exchange.getIn().getBody(UserInput.class).get_embedded().getUdmobject().get(0)
                                .getProperties().getUsername();
                        String encryptedPassword = exchange.getIn().getHeader("password", String.class).replaceAll(" ",
                                "+");

                        String password = new String(AESEncryptionUtil
                                .decrypt("9Y@ov#XLt@bNN@We^fqDypo%v5vv$7Ah".getBytes(), encryptedPassword));

                        String concat = username + ":" + password;
                        exchange.setProperty("auth", "Basic " + Base64.getEncoder().encodeToString(concat.getBytes()));

                        exchange.getIn().setHeader("Authorization",
                                "Basic " + Base64.getEncoder().encodeToString(concat.getBytes()));

                        return new UserVerifyPassword(username);

                    } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                            | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                            | IllegalArgumentException e) {
                        // Do nothing
                        return null;
                    } finally {
                        // Do nothing
                    }
                })
                .marshal().json()

                .to("direct:verifyPasswordService")
                .when(exchange -> {
                    try {
                        if (exchange.getIn().getBody(UserInput.class).getResults() != 1) {
                            return true;
                        }
                        return false;
                    } finally {
                        // DO nothing
                    }
                })
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(404))
                .setBody(constant(new Response("99", "DATA NOT FOUND")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(UnauthorizedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("94", "MUST CHANGE PASSWORD AFTER CREATE USER")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .handled(true)
                .end()

                .onException(AccessDeniedException.class)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("90", "INVALID USER ROLE")))
                .handled(true)
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

        from("direct:verifyPasswordService")
                .removeHeaders("Camel*")
                .setHeader(Exchange.HTTP_METHOD, constant("PUT"))
                .setHeader("Content-Type", constant("application/json"))

                .toD("{{ucs.baseUrl}}/univention/udm/users/user/?query[uid]=" + "${exchangeProperty.MyBodyProperty}")

                .log(("Sending response ${body}"))

                .onException(HttpOperationFailedException.class)
                .onWhen(exceptionMessage().not().contains("statusCode: 401"))
                .handled(true)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(200))
                .setBody(constant(new Response("00", "SUCCESS")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

                .onException(HttpOperationFailedException.class)
                .onWhen(exceptionMessage().contains("statusCode: 401"))
                .handled(true)
                .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(401))
                .setBody(constant(new Response("96", "INVALID PASSWORD/ENCRYPTION ALGORITHM")))
                .marshal().json()
                .log(("Sending response ${body}"))
                .end()

        ;

    }

    private static class InsecureX509TrustManager extends X509ExtendedTrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket)
                throws CertificateException {

        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)
                throws CertificateException {

        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

}
