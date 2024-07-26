package org.i3mid.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class UDMProperties implements Serializable {
    private String username;
    private String firstname;
    private String lastname;
    private String password;
    private String mailPrimaryAddress;
    @JsonProperty("e-mail")
    private String[] email;
    private String employeeNumber;
    private boolean disabled;
    private String overridePWLength;
    private boolean pwdChangeNextLogin;
    private String organisation;
    private String passwordexpiry;
    private String[] departmentNumber;
    private String dn;
    private String displayName;
    private boolean overridePWHistory;
    private List<String> groups;

    
    
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getFirstname() {
        return firstname;
    }
    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }
    public String getLastname() {
        return lastname;
    }
    public void setLastname(String lastname) {
        this.lastname = lastname;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getMailPrimaryAddress() {
        return mailPrimaryAddress;
    }
    public void setMailPrimaryAddress(String mailPrimaryAddress) {
        this.mailPrimaryAddress = mailPrimaryAddress;
    }
    public String[] getEmail() {
        return email;
    }
    public void setEmail(String[] email) {
        this.email = email;
    }
    public String getEmployeeNumber() {
        return employeeNumber;
    }
    public void setEmployeeNumber(String employeeNumber) {
        this.employeeNumber = employeeNumber;
    }
    public boolean getDisabled() {
        return disabled;
    }
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }
    public String getOverridePWLength() {
        return overridePWLength;
    }
    public void setOverridePWLength(String overridePWLength) {
        this.overridePWLength = overridePWLength;
    }
    public boolean getPwdChangeNextLogin() {
        return pwdChangeNextLogin;
    }
    public void setPwdChangeNextLogin(boolean pwdChangeNextLogin) {
        this.pwdChangeNextLogin = pwdChangeNextLogin;
    }
    public String getOrganisation() {
        return organisation;
    }
    public void setOrganisation(String organisation) {
        this.organisation = organisation;
    }
    public String getPasswordexpiry() {
        return passwordexpiry;
    }
    public void setPasswordexpiry(String passwordexpiry) {
        this.passwordexpiry = passwordexpiry;
    }
    public String[] getDepartmentNumber() {
        return departmentNumber;
    }
    public void setDepartmentNumber(String[] departmentNumber) {
        this.departmentNumber = departmentNumber;
    }
    public String getDn() {
        return dn;
    }
    public void setDn(String dn) {
        this.dn = dn;
    }
    public String getDisplayName() {
        return displayName;
    }
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
    public boolean getOverridePWHistory() {
        return overridePWHistory;
    }
    public void setOverridePWHistory(boolean overridePWHistory) {
        this.overridePWHistory = overridePWHistory;
    }

    public List<String> getGroups() {
        return groups;
    }
    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    @Override
    public String toString() {
        return "UDMProperties{" +
                "username='" + username + '\'' +
                ", firstname='" + firstname + '\'' +
                ", lastname='" + lastname + '\'' +
                ", password='" + password + '\'' +
                ", mailPrimaryAddress='" + mailPrimaryAddress + '\'' +
                ", e-mail='" + email + '\'' +
                ", employeeNumber='" + employeeNumber + '\'' +
                ", disabled='" + disabled + '\'' +
                ", ovveridePWHistory='" + overridePWHistory + '\'' +
                ", overridePWLength='" + overridePWLength + '\'' +
                ", pwdChangeNextLogin='" + pwdChangeNextLogin + '\'' +
                ", organisation='" + organisation + '\'' +
                ", passwordexpiry='" + passwordexpiry + '\'' +
                ", departmentNumber=" + Arrays.toString(departmentNumber) +
                ", dn='" + dn + '\'' +
                ", displayName='" + displayName + '\'' +
                '}';
    }
}
