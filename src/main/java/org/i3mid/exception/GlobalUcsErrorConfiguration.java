package org.i3mid.exception;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteConfigurationBuilder;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.apache.camel.model.RouteConfigurationDefinition;
import org.i3mid.models.Response;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class GlobalUcsErrorConfiguration extends RouteConfigurationBuilder {

    @Override
    public void configuration() {
        RouteConfigurationDefinition config = routeConfiguration();

        // 1. Kasus URL UCS salah / DNS tidak ditemukan / Host null
        config.onException(UnknownHostException.class)
            .process(this::recordErrorMetadata)
            .removeHeader("Authorization")
            .handled(true)
            .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(502))
            .setBody(constant(new Response("502", "UCS Host Unreachable")))
            .marshal().json()
            .log("[${exchangeId}] ${exchangeProperty.reqInfo} | errorType=UNKNOWN_HOST | " +
                 "detail=${exception.message} | ucsUrl=${exchangeProperty.targetUcsUrl}, " +
                 "responseCode=502, latency=${exchangeProperty.ucsLatency} ms");

        // 2. Kasus Connection Refused / Network Unreachable
        config.onException(ConnectException.class, NoRouteToHostException.class)
            .process(this::recordErrorMetadata)
            .removeHeader("Authorization")
            .handled(true)
            .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(503))
            .setBody(constant(new Response("503", "UCS Connection Refused")))
            .marshal().json()
            .log("[${exchangeId}] ${exchangeProperty.reqInfo} | errorType=CONNECT_FAILED | " +
                 "detail=${exception.message} | ucsUrl=${exchangeProperty.targetUcsUrl}, " +
                 "responseCode=503, latency=${exchangeProperty.ucsLatency} ms");

        // 3. Kasus UCS Hang / Read atau Connect Timeout
        config.onException(SocketTimeoutException.class)
            .process(this::recordErrorMetadata)
            .removeHeader("Authorization")
            .handled(true)
            .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(504))
            .setBody(constant(new Response("504", "UCS Connection Timeout")))
            .marshal().json()
            .log("[${exchangeId}] ${exchangeProperty.reqInfo} | errorType=TIMEOUT | " +
                 "detail=${exception.message} | ucsUrl=${exchangeProperty.targetUcsUrl}, " +
                 "responseCode=504, latency=${exchangeProperty.ucsLatency} ms");

        // 4. Kasus HTTP Operation Failed yang tidak ditangani spesifik oleh route (misal 401/500/502/503 dari UCS)
        config.onException(HttpOperationFailedException.class)
            .process(this::recordErrorMetadata)
            .removeHeader("Authorization")
            .handled(true)
            .process(exchange -> {
                HttpOperationFailedException ex = exchange.getProperty(
                    Exchange.EXCEPTION_CAUGHT, HttpOperationFailedException.class);
                int upstreamStatus = ex != null ? ex.getStatusCode() : 502;
                exchange.setProperty("upstreamStatus", upstreamStatus);
                exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 502);
                exchange.getIn().setBody(new Response("502", "Upstream UCS HTTP Error (" + upstreamStatus + ")"));
            })
            .marshal().json()
            .log("[${exchangeId}] ${exchangeProperty.reqInfo} | errorType=HTTP_OPERATION_FAILED | " +
                 "upstreamStatus=${exchangeProperty.upstreamStatus} | detail=${exception.message} | " +
                 "ucsUrl=${exchangeProperty.targetUcsUrl}, responseCode=502, " +
                 "latency=${exchangeProperty.ucsLatency} ms");

        // 5. Fallback untuk IOException jaringan lainnya (misal SSLHandshakeException / Broken pipe)
        config.onException(IOException.class)
            .process(this::recordErrorMetadata)
            .removeHeader("Authorization")
            .handled(true)
            .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(502))
            .setBody(constant(new Response("502", "UCS IO/SSL Communication Error")))
            .marshal().json()
            .log("[${exchangeId}] ${exchangeProperty.reqInfo} | errorType=IO_ERROR | " +
                 "detail=${exception.class.name}: ${exception.message} | " +
                 "ucsUrl=${exchangeProperty.targetUcsUrl}, responseCode=502, " +
                 "latency=${exchangeProperty.ucsLatency} ms");
    }

    private void recordErrorMetadata(Exchange exchange) {
        Long start = exchange.getProperty("ucsStartTime", Long.class);
        long latency = (start != null) ? (System.currentTimeMillis() - start) : 0L;
        exchange.setProperty("ucsLatency", latency);

        String toEndpoint = exchange.getProperty(Exchange.TO_ENDPOINT, String.class);
        if (toEndpoint != null) {
            int queryIdx = toEndpoint.indexOf('?');
            exchange.setProperty("targetUcsUrl", queryIdx > 0 ? toEndpoint.substring(0, queryIdx) : toEndpoint);
        } else {
            exchange.setProperty("targetUcsUrl", "unknown");
        }
    }
}