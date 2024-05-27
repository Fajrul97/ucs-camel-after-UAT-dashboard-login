package org.i3mid.models;

import java.io.Serializable;

public class Response implements Serializable {
    private String ResponseCode;
    private String ResponseDescription;

    public Response(String responseCode, String responseDescription) {
        ResponseCode = responseCode;
        ResponseDescription = responseDescription;
    }

    public String getResponseCode() {
        return ResponseCode;
    }
    public void setResponseCode(String responseCode) {
        ResponseCode = responseCode;
    }
    public String getResponseDescription() {
        return ResponseDescription;
    }
    public void setResponseDescription(String responseDescription) {
        ResponseDescription = responseDescription;
    }
}
