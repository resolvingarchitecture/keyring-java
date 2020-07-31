package ra.keyring;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import ra.common.DLC;
import ra.common.Envelope;

import java.io.File;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Logger;

import static ra.keyring.KeyRingService.PASSWORD_HASH_STRENGTH_64;

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

//    @Test
//    public void generateKeyRingsCollectionTest() {
//        GenerateKeyRingCollectionsRequest req = new GenerateKeyRingCollectionsRequest();
//        req.keyRingImplementation = "ra.keyring.OpenPGPKeyRing";
//        req.keyRingUsername = "Anon1";
//        req.keyRingPassphrase = "1234";
//        req.hashStrength = PASSWORD_HASH_STRENGTH_64;
//        Envelope e = Envelope.documentFactory();
//        DLC.addData(GenerateKeyRingCollectionsRequest.class, req, e);
//        DLC.addRoute(KeyRingService.class.getName(), KeyRingService.OPERATION_GENERATE_KEY_RINGS_COLLECTIONS, e);
//        // Ratchet route
//        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
//        File pkf = new File(service.getServiceDirectory(), req.keyRingUsername+".pkr");
//        if(pkf.exists()) {
//            Assert.assertTrue(pkf.delete());
//        }
//        File skf = new File(service.getServiceDirectory(), req.keyRingUsername+".skr");
//        if(skf.exists()) {
//            Assert.assertTrue(skf.delete());
//        }
//        long start = new Date().getTime();
//        service.handleDocument(e);
//        long end = new Date().getTime();
//        LOG.info("Key generation took: "+(end-start)+" ms.");
//        Assert.assertTrue(pkf.exists());
//        Assert.assertTrue(skf.exists());
//        Assert.assertTrue((end-start) < 30000); // < 30 seconds
//    }

//    @Test
//    public void generateKeyRingsTest() {
//        GenerateKeyRingsRequest req = new GenerateKeyRingsRequest();
//        req.keyRingImplementation = "ra.keyring.OpenPGPKeyRing";
//        req.keyRingUsername = "Anon2";
//        req.keyRingPassphrase = "1234";
//        req.alias = "Anon2-Sharon";
//        req.aliasPassphrase = "5678";
//        Envelope e = Envelope.documentFactory();
//        DLC.addData(GenerateKeyRingsRequest.class, req, e);
//        DLC.addRoute(KeyRingService.class.getName(), KeyRingService.OPERATION_GENERATE_KEY_RINGS, e);
//        // Ratchet Route
//        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
//        File pkf = new File(service.getServiceDirectory(), req.keyRingUsername+".pkr");
//        if(pkf.exists()) {
//            Assert.assertTrue(pkf.delete());
//        }
//        File skf = new File(service.getServiceDirectory(), req.keyRingUsername+".skr");
//        if(skf.exists()) {
//            Assert.assertTrue(skf.delete());
//        }
//        long start = new Date().getTime();
//        service.handleDocument(e);
//        long end = new Date().getTime();
//        LOG.info("Key generation took: "+(end-start)+" ms.");
//        Assert.assertTrue(pkf.exists());
//        Assert.assertTrue(skf.exists());
//        Assert.assertTrue((end-start) < 30000); // < 30 seconds
//    }

    @Test
    public void authenticationTest() {
        AuthNRequest req = new AuthNRequest();
        req.keyRingUsername = "Anon3";
        req.keyRingPassphrase = "1234";
        req.alias = "Anon3-Barbara";
        req.aliasPassphrase = "5678";
        req.autoGenerate = true;
        Envelope e = Envelope.documentFactory();
        DLC.addData(AuthNRequest.class, req, e);
        DLC.addRoute(KeyRingService.class.getName(), KeyRingService.OPERATION_AUTHN, e);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        File pkf = new File(service.getServiceDirectory(), req.keyRingUsername+".pkr");
        if(pkf.exists()) {
            Assert.assertTrue(pkf.delete());
        }
        File skf = new File(service.getServiceDirectory(), req.keyRingUsername+".skr");
        if(skf.exists()) {
            Assert.assertTrue(skf.delete());
        }
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        LOG.info("Authentication took: "+(end-start)+" ms.");
        Assert.assertTrue(pkf.exists());
        Assert.assertTrue(skf.exists());
        Assert.assertTrue((end-start) < 30000); // < 30 seconds
        Assert.assertTrue(req.identityPublicKey!=null && req.identityPublicKey.isIdentityKey() && req.identityPublicKey.getAlias()!=null && req.identityPublicKey.getAddress()!=null);
    }
}
