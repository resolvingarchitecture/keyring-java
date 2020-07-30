package ra.keyring;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Properties;
import java.util.logging.Logger;

public class KeyRingServiceTest {

    private static final Logger LOG = Logger.getLogger(KeyRingServiceTest.class.getName());

    private static MockProducer producer;
    private static KeyRingService service;
    private static Properties props;
    private static boolean serviceRunning = false;

    @BeforeClass
    public static void init() {
        LOG.info("Init...");
        props = new Properties();
        producer = new MockProducer();
        service = new KeyRingService(producer, null);
        serviceRunning = service.start(props);
    }

    @AfterClass
    public static void tearDown() {
        LOG.info("Teardown...");
        service.gracefulShutdown();
    }

    @Test
    public void verifyInitializedTest() {
        Assert.assertTrue(serviceRunning);
    }
}
