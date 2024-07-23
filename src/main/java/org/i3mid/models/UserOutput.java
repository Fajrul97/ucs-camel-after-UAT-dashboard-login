package org.i3mid.models;

import org.i3mid.exception.ResultMoreThanOneException;
import org.i3mid.exception.ResultNotFoundException;

import java.text.SimpleDateFormat;
import java.util.Date;

public class UserOutput {
    private String uid;
    private String loginDisabled;
    private String sn;
    private boolean pwdChangeNextLogin;
    private String loginTime;
    private String passwordMinimumLength;
    private String passwordRequired;
    private String passwordUniqueRequired;
    private String objectClass;
    private String passwordExpirationInterval;
    private String givenName;
    private String co;
    private String cn;
    private String[] departmentNumber;
    private String ACL;
    private String displayName;
    private String passwordExpirationTime;
    
    public UserOutput(UserInput userInput) throws ResultMoreThanOneException, ResultNotFoundException {
        // System.out.println("Result = " + userInput.getResults());
        if (userInput.getResults() == 1 ) {
            UDMObject userObject = userInput.get_embedded().getUdmobject().get(0);
            this.uid = userObject.getUuid();
            this.loginDisabled = String.valueOf(userObject.getProperties().getDisabled());
            this.sn = null;
            this.pwdChangeNextLogin = userObject.getProperties().getPwdChangeNextLogin();
            this.loginTime = new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date());
            this.passwordMinimumLength = userObject.getProperties().getOverridePWLength();
            this.passwordRequired = String.valueOf(userObject.getProperties().getPassword() != null);
            this.passwordUniqueRequired = null;
            this.objectClass = userObject.getProperties().getOrganisation();
            this.passwordExpirationInterval = userObject.getProperties().getPasswordexpiry();
            this.givenName = userObject.getProperties().getFirstname() + " " + userObject.getProperties().getLastname();
            this.co = null;
            this.cn = null;
            this.departmentNumber = userObject.getProperties().getDepartmentNumber();
            this.ACL = userObject.getProperties().getDn();
            this.displayName = userObject.getProperties().getDisplayName();
            this.passwordExpirationTime = userObject.getProperties().getPasswordexpiry();
        } else if (userInput.getResults() == 0) {
            throw new ResultNotFoundException("User queried is not found");
        } else if (userInput.getResults() > 1) {
            throw new ResultMoreThanOneException("Duplicate user ID found");
        }

    }

    public String getUid() {
        return uid;
    }
    public void setUid(String uid) {
        this.uid = uid;
    }
    public String getLoginDisabled() {
        return loginDisabled;
    }
    public void setLoginDisabled(String loginDisabled) {
        this.loginDisabled = loginDisabled;
    }
    public String getSn() {
        return sn;
    }
    public void setSn(String sn) {
        this.sn = sn;
    }
    public boolean getPwdChangeNextLogin() {
        return pwdChangeNextLogin;
    }
    public void setPwdChangeNextLogin(boolean pwdChangeNextLogin) {
        this.pwdChangeNextLogin = pwdChangeNextLogin;
    }
    public String getLoginTime() {
        return loginTime;
    }
    public void setLoginTime(String loginTime) {
        this.loginTime = loginTime;
    }
    public String getPasswordMinimumLength() {
        return passwordMinimumLength;
    }
    public void setPasswordMinimumLength(String passwordMinimumLength) {
        this.passwordMinimumLength = passwordMinimumLength;
    }
    public String getPasswordRequired() {
        return passwordRequired;
    }
    public void setPasswordRequired(String passwordRequired) {
        this.passwordRequired = passwordRequired;
    }
    public String getPasswordUniqueRequired() {
        return passwordUniqueRequired;
    }
    public void setPasswordUniqueRequired(String passwordUniqueRequired) {
        this.passwordUniqueRequired = passwordUniqueRequired;
    }
    public String getObjectClass() {
        return objectClass;
    }
    public void setObjectClass(String objectClass) {
        this.objectClass = objectClass;
    }
    public String getPasswordExpirationInterval() {
        return passwordExpirationInterval;
    }
    public void setPasswordExpirationInterval(String passwordExpirationInterval) {
        this.passwordExpirationInterval = passwordExpirationInterval;
    }
    public String getGivenName() {
        return givenName;
    }
    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }
    public String getCo() {
        return co;
    }
    public void setCo(String co) {
        this.co = co;
    }
    public String getCn() {
        return cn;
    }
    public void setCn(String cn) {
        this.cn = cn;
    }
    public String[] getDepartmentNumber() {
        return departmentNumber;
    }
    public void setDepartmentNumber(String[] departmentNumber) {
        this.departmentNumber = departmentNumber;
    }
    public String getACL() {
        return ACL;
    }
    public void setACL(String ACL) {
        this.ACL = ACL;
    }
    public String getDisplayName() {
        return displayName;
    }
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
    public String getPasswordExpirationTime() {
        return passwordExpirationTime;
    }
    public void setPasswordExpirationTime(String passwordExpirationTime) {
        this.passwordExpirationTime = passwordExpirationTime;
    }

    @Override
    public String toString() {
        return "UserOutput{" +
                "uid='" + uid + '\'' +
                ", loginDisabled='" + loginDisabled + '\'' +
                ", sn='" + sn + '\'' +
                ", pwdChangeNextLogin='" + pwdChangeNextLogin + '\'' +
                ", loginTime='" + loginTime + '\'' +
                ", passwordMinimumLength='" + passwordMinimumLength + '\'' +
                ", passwordRequired='" + passwordRequired + '\'' +
                ", passwordUniqueRequired='" + passwordUniqueRequired + '\'' +
                ", objectClass='" + objectClass + '\'' +
                ", passwordExpirationInterval='" + passwordExpirationInterval + '\'' +
                ", givenName='" + givenName + '\'' +
                ", co='" + co + '\'' +
                ", cn='" + cn + '\'' +
                ", departmentNumber='" + departmentNumber + '\'' +
                ", ACL='" + ACL + '\'' +
                ", displayName='" + displayName + '\'' +
                ", passwordExpirationTime='" + passwordExpirationTime + '\'' +
                '}';
    }
}
