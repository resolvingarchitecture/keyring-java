package ra.keyring;

import ra.common.Client;
import ra.common.Envelope;
import ra.common.messaging.MessageProducer;

import java.util.logging.Logger;

public class MockProducer implements MessageProducer {

    private static Logger LOG = Logger.getLogger(MockProducer.class.getName());

    @Override
    public boolean send(Envelope envelope) {
        return false;
    }

    @Override
    public boolean send(Envelope envelope, Client client) {
        return false;
    }
}
