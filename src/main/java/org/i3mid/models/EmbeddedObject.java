package org.i3mid.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class EmbeddedObject implements Serializable {
    @JsonProperty("udm:object")
    private List<UDMObject> udmobject;
    public List<UDMObject> getUdmobject() {
        return udmobject;
    }
    public void setUdmobject(List<UDMObject> udmobject) {
        this.udmobject = udmobject;
    }

    @Override
    public String toString() {
        return "EmbeddedObject{" +
                "udmobject=" + udmobject +
                '}';
    }
}

