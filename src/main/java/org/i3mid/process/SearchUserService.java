package org.i3mid.process;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.i3mid.exception.ResultNotFoundException;
import org.i3mid.models.UDMObject;
import org.i3mid.models.UserInput;

public class SearchUserService implements Processor {
    @Override
    public void process(Exchange exchange) throws Exception {
        UserInput input = exchange.getIn().getBody(UserInput.class);
        int id = exchange.getIn().getHeader("id", Integer.class);

        if (!(exchange.getIn().getBody() instanceof UDMObject)) {
            throw new ResultNotFoundException("User with ID " + id + " is not found in query");
        }
    }
}
