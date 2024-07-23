package org.i3mid.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserInput implements Serializable {
    private int results;
    private EmbeddedObject _embedded;

    public int getResults() {
        return results;
    }
    public void setResults(int results) {
        this.results = results;
    }
    public EmbeddedObject get_embedded() {
        return _embedded;
    }
    public void set_embedded(EmbeddedObject _embedded) {
        this._embedded = _embedded;
    }

    @Override
    public String toString() {
        return "UserInput{" +
                "results=" + results +
                ", _embedded=" + _embedded +
                '}';
    }
}
