package org.i3mid.models;

public class ChangePasswordProperties {
    
    
    private String username;
    private String password;
    private boolean overridePWHistory;

    

    public ChangePasswordProperties() {
    }
    
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public boolean isOverridePWHistory() {
        return overridePWHistory;
    }
    public void setOverridePWHistory(boolean overridePWHistory) {
        this.overridePWHistory = overridePWHistory;
    }

    @Override
    public String toString() {
        return "ChangePasswordProperties [username=" + username + ", password=" + password + ", overridePWHistory="
                + overridePWHistory + "]";
    }

}
