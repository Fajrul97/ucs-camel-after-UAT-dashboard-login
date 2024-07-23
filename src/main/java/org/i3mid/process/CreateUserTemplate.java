package org.i3mid.process;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.i3mid.models.UDMObject;

import java.text.SimpleDateFormat;
import java.util.Date;

public class CreateUserTemplate implements Processor {
    @Override
    public void process(Exchange exchange) throws Exception {
        String[] departmentNumber = {exchange.getIn().getHeader("departmentNumber", String.class)};
        String id = exchange.getIn().getHeader("id", String.class);
        String givenName = exchange.getIn().getHeader("givenName", String.class);
        Date inputBirthday = new SimpleDateFormat("yyyyMMdd")
                .parse(exchange.getIn().getHeader("birthDate", String.class));
        String birthday = new SimpleDateFormat("yyyy-MM-dd").format(inputBirthday);
        String displayName = exchange.getIn().getHeader("displayName", String.class);

        UDMObject userTemplate = new UDMObject("users/user", departmentNumber,
                false, null, null, true, id,
                "", givenName, birthday, null, displayName,
                new SimpleDateFormat("yyyyMMdd").format(inputBirthday), null);

        exchange.getIn().setBody(userTemplate);
    }
}


