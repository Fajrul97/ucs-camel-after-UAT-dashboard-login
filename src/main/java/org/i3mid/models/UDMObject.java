package org.i3mid.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UDMObject implements Serializable {
    // @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;
    private String objectType;
    @JsonProperty("properties")
    private UDMProperties properties;
    // @JsonInclude(JsonInclude.Include.NON_NULL)
    private String uuid;
    //@JsonInclude(JsonInclude.Include.NON_NULL)
    private String dn;
    private String position;


    public UDMObject() {
    }
    public UDMObject(String objectType, String[] departmentNumber, boolean disabled,
                     String overridePWLength, String organisation, boolean pwdChangeNextLogin,
                     String username, String firstname, String lastname, String mailPrimaryAddress,
                     String employeeNumber, String displayName, String password,
                     String passwordexpiry) {
        this.objectType = objectType;
        UDMProperties properties = new UDMProperties();
        properties.setDepartmentNumber(departmentNumber);
        properties.setDisabled(disabled);
        properties.setOverridePWLength(overridePWLength);
        properties.setOrganisation(organisation);
        properties.setPwdChangeNextLogin(pwdChangeNextLogin);
        properties.setUsername(username);
        properties.setFirstname(firstname);
        properties.setLastname(lastname);
        properties.setMailPrimaryAddress(mailPrimaryAddress);
        properties.setEmployeeNumber(employeeNumber);
        properties.setDisplayName(displayName);
        properties.setPassword(password);
        properties.setPasswordexpiry(passwordexpiry);
        this.properties = properties;
    }

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getObjectType() {
        return objectType;
    }
    public void setObjectType(String objectType) {
        this.objectType = objectType;
    }
    public String getUuid() {
        return uuid;
    }
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
    public UDMProperties getProperties() {
        return properties;
    }
    public void setProperties(UDMProperties properties) {
        this.properties = properties;
    }
    public String getDn() {
        return dn;
    }
    public void setDn(String dn) {
        this.dn = dn;
    }
    public String getPosition() {
        return position;
    }
    public void setPosition(String position) {
        this.position = position;
    }
    
    @Override
    public String toString() {
        return "UDMObject{" +
                "id='" + id + '\'' +
                ", objectType='" + objectType + '\'' +
                ", properties=" + properties +
                ", uuid='" + uuid + '\'' +
                '}';
    }
}
