package org.i3mid.models;

import java.io.Serializable;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class ChangePasswordRequest implements Serializable {
    private String uuid;
    private String position;
    private String uri;
    private ObjectNode options;
    private ObjectNode policies;
    private ChangePasswordProperties properties;

    public ChangePasswordRequest() {
        // Default
    }

    
    public ChangePasswordRequest(UserInput userInput, String newPassword) {
        this.uuid = userInput.get_embedded().getUdmobject().get(0).getUuid();
        this.position = userInput.get_embedded().getUdmobject().get(0).getPosition();
        this.uri = "{{ucs.baseUrl.write}}/univention/udm/users/passwd/" + this.position;
            ObjectMapper mapper = new ObjectMapper();

        this.options= mapper.createObjectNode();
        this.policies = mapper.createObjectNode();

        
        
        ChangePasswordProperties properties = new ChangePasswordProperties();
        properties.setUsername(userInput.get_embedded().getUdmobject().get(0).getProperties().getUsername());
        properties.setPassword(newPassword);
        this.properties = properties;

        // System.out.println("test");
       
    }

    public String getUri() {
        return uri;
    }
    public void setUri(String uri) {
        this.uri = uri;
    }
    public ObjectNode getOptions() {
        return options;
    }
    public void setOptions(ObjectNode options) {
        this.options = options;
    }
    public ObjectNode getPolicies() {
        return policies;
    }
    public void setPolicies(ObjectNode policies) {
        this.policies = policies;
    }
    public String getUuid() {
        return uuid;
    }
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
    public String getPosition() {
        return position;
    }
    public void setPosition(String position) {
        this.position = position;
    }
    public ChangePasswordProperties getProperties() {
        return properties;
    }
    public void setProperties(ChangePasswordProperties properties) {
        this.properties = properties;
    }


    @Override
    public String toString() {
        return "ChangePasswordRequest [uuid=" + uuid + ", position=" + position + ", uri=" + uri + ", options="
                + options + ", policies=" + policies + ", properties=" + properties + "]";
        
    }

}
