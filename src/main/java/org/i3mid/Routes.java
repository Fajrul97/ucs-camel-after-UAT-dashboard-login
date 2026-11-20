package org.i3mid;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.http.HttpComponent;
import org.apache.camel.support.jsse.SSLContextParameters;
import org.apache.camel.support.jsse.TrustManagersParameters;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class Routes extends RouteBuilder {

        @Override
        public void configure() throws Exception {
                HttpComponent httpComponent = getContext().getComponent("https", HttpComponent.class);

                httpComponent.setMaxTotalConnections(200);
                httpComponent.setConnectionsPerRoute(200);
                httpComponent.setConnectionTimeToLive(60000L);

                TrustManagersParameters trustManagersParameters = new TrustManagersParameters();
                X509ExtendedTrustManager extendedTrustManager = new InsecureX509TrustManager();
                trustManagersParameters.setTrustManager(extendedTrustManager);

                SSLContextParameters sslContextParameters = new SSLContextParameters();
                sslContextParameters.setTrustManagers(trustManagersParameters);
                httpComponent.setSslContextParameters(sslContextParameters);
                httpComponent.setX509HostnameVerifier(new AllowAllHostnameVerifier());

                from("timer:foo?repeatCount=1")
                                .routeId("startup-jvm-check")
                                .log("JVM Version: ${sys.java.runtime.version}");

                rest("/ldapService")
                                .get().to("direct:restService");

                from("direct:restService")
                                .routeId("ldap-gateway-router")
                                .setProperty("reqInfo", simple(
                                                "method=${header.CamelHttpMethod}, path=${header.CamelHttpPath}, " +
                                                                "operation=${header.operation}, id=${header.id}, " +
                                                                "remote=${header.CamelVertxPlatformHttpRemoteAddress}"))

                                .choice()
                                .when(simple("${header.operation} == 'search'"))
                                .to("direct:searchUserService")
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
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                                throws CertificateException {

                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                                throws CertificateException {

                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                }
        }

}
