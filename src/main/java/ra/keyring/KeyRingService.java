package ra.keyring;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import ra.common.Envelope;
import ra.common.crypto.EncryptionAlgorithm;
import ra.common.identity.PublicKey;
import ra.common.messaging.MessageProducer;
import ra.common.route.Route;
import ra.common.service.BaseService;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;
import ra.common.SystemVersion;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * Manages keys for the bus and its user.
 *
 * @author ObjectOrange
 */
public class KeyRingService extends BaseService {

    public static final String OPERATION_GENERATE_KEY_RINGS_COLLECTIONS = "GENERATE_KEY_RINGS_COLLECTIONS";
    public static final String OPERATION_GENERATE_KEY_RINGS = "GENERATE_KEY_RINGS";
    public static final String OPERATION_AUTHN = "AUTHN";
    public static final String OPERATION_ENCRYPT = "ENCRYPT";
    public static final String OPERATION_DECRYPT = "DECRYPT";
    public static final String OPERATION_ENCRYPT_SYMMETRIC = "ENCRYPT_SYMMETRIC";
    public static final String OPERATION_DECRYPT_SYMMETRIC = "DECRYPT_SYMMETRIC";
    public static final String OPERATION_SIGN = "SIGN";
    public static final String OPERATION_VERIFY_SIGNATURE = "VERIFY_SIGNATURE";
    public static final String OPERATION_VOUCH = "VOUCH";
    public static final String OPERATION_RELOAD = "RELOAD";

    public static final int PASSWORD_HASH_STRENGTH_64 = 0x10; // About 64 iterations for SHA-256
    public static final int PASSWORD_HASH_STRENGTH_128 = 0x20; // About 128
    public static final int PASSWORD_HASH_STRENGTH_256 = 0x30; // About 256
    public static final int PASSWORD_HASH_STRENGTH_512 = 0x40; // About 512
    public static final int PASSWORD_HASH_STRENGTH_1k = 0x50; // About 1k
    public static final int PASSWORD_HASH_STRENGTH_2k = 0x60; // About 2k
    public static final int PASSWORD_HASH_STRENGTH_4k = 0x70; // About 4k
    public static final int PASSWORD_HASH_STRENGTH_8k = 0x80; // About 8k
    public static final int PASSWORD_HASH_STRENGTH_16k = 0x90; // About16k
    public static final int PASSWORD_HASH_STRENGTH_32k = 0xa0; // About 32k
    public static final int PASSWORD_HASH_STRENGTH_64k = 0xb0; // About 64k
    public static final int PASSWORD_HASH_STRENGTH_128k = 0xc0; // About 128k
    public static final int PASSWORD_HASH_STRENGTH_256k = 0xd0; // About 256k
    public static final int PASSWORD_HASH_STRENGTH_512k = 0xe0; // About 512k
    public static final int PASSWORD_HASH_STRENGTH_1M = 0xf0; // About 1 million
    public static final int PASSWORD_HASH_STRENGTH_2M = 0xff; // About 2 million

    private static final Logger LOG = Logger.getLogger(KeyRingService.class.getName());

    private Properties properties = new Properties();

    private Map<String, KeyRing> keyRings = new HashMap<>();

    public KeyRingService() {}

    public KeyRingService(MessageProducer producer, ServiceStatusObserver observer) {
        super(producer, observer);
    }

    @Override
    public void handleDocument(Envelope e) {
        Route route = e.getRoute();
        KeyRing keyRing;
        switch (route.getOperation()) {
            case OPERATION_GENERATE_KEY_RINGS_COLLECTIONS: {
                LOG.info("Generate Key Rings Collections request received.");
                GenerateKeyRingCollectionsRequest r = (GenerateKeyRingCollectionsRequest) e.getData(GenerateKeyRingCollectionsRequest.class);
                if(r == null) {
                    LOG.warning("GenerateKeyRingCollectionsRequest required.");
                    r = new GenerateKeyRingCollectionsRequest();
                    r.statusCode = GenerateKeyRingCollectionsRequest.REQUEST_REQUIRED;
                    e.addData(GenerateKeyRingCollectionsRequest.class, r);
                    break;
                }
                File f;
                if(r.location == null || r.location.isEmpty()) {
                    // default
                    f = getServiceDirectory();
                    r.location = f.getAbsolutePath();
                } else {
                    f = new File(r.location);
                }
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.keyRingUsername == null) {
                    LOG.warning("KeyRing username required.");
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_USERNAME_REQUIRED;
                    break;
                }
                if(r.keyRingPassphrase == null) {
                    LOG.warning("KeyRing passphrase required.");
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.hashStrength < PASSWORD_HASH_STRENGTH_64) {
                    r.hashStrength = PASSWORD_HASH_STRENGTH_64; // minimum
                }
                if(r.keyRingImplementation == null) {
                    r.keyRingImplementation = OpenPGPKeyRing.class.getName(); // Default
                }
                try {
                    keyRing = keyRings.get(r.keyRingImplementation);
                    if(keyRing == null) {
                        LOG.warning("KeyRing implementation unknown: "+r.keyRingImplementation);
                        r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                        return;
                    }
                    keyRing.generateKeyRingCollections(r);
                } catch (Exception ex) {
                    r.exception = ex;
                }
                break;
            }
            case OPERATION_AUTHN: {
                AuthNRequest r = (AuthNRequest)e.getData(AuthNRequest.class);
                if(r==null) {
                    r = new AuthNRequest();
                    r.statusCode = AuthNRequest.REQUEST_REQUIRED;
                    e.addData(AuthNRequest.class, r);
                    break;
                }
                File f;
                if(r.location == null || r.location.isEmpty()) {
                    // Set locally
                    f = getServiceDirectory();
                    r.location = f.getAbsolutePath();
                } else {
                    f = new File(r.location);
                }
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = AuthNRequest.KEYRING_LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.keyRingUsername == null) {
                    LOG.warning("KeyRing username required.");
                    r.statusCode = AuthNRequest.KEY_RING_USERNAME_REQUIRED;
                    break;
                }
                if(r.keyRingPassphrase == null) {
                    LOG.warning("KeyRing passphrase required.");
                    r.statusCode = AuthNRequest.KEY_RING_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.alias == null || r.alias.isEmpty()) {
                    r.statusCode = AuthNRequest.ALIAS_REQUIRED;
                    break;
                }
                if(r.aliasPassphrase == null || r.aliasPassphrase.isEmpty()) {
                    r.statusCode = AuthNRequest.ALIAS_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.keyRingImplementation == null) {
                    r.keyRingImplementation = OpenPGPKeyRing.class.getName(); // Default
                }
                try {
                    keyRing = keyRings.get(r.keyRingImplementation);
                    if(keyRing == null) {
                        LOG.warning("KeyRing implementation unknown: "+r.keyRingImplementation);
                        r.statusCode = AuthNRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                        return;
                    }
                    PGPPublicKeyRingCollection c = null;
                    try {
                        c = keyRing.getPublicKeyRingCollection(r.location, r.keyRingUsername, r.keyRingPassphrase);
                    } catch (IOException e1) {
                        LOG.info("No key ring collection found.");
                    } catch (PGPException e1) {
                        LOG.info("No key ring collection found.");
                    }
                    if(c==null) {
                        // No collection found
                        if(r.autoGenerate) {
                            GenerateKeyRingCollectionsRequest gkr = new GenerateKeyRingCollectionsRequest();
                            gkr.location = r.location;
                            gkr.keyRingUsername = r.keyRingUsername;
                            gkr.keyRingPassphrase = r.keyRingPassphrase;
                            keyRing.generateKeyRingCollections(gkr);
                            if(gkr.identityPublicKey!=null) r.identityPublicKey = gkr.identityPublicKey;
                            if(gkr.encryptionPublicKey!=null) r.encryptionPublicKey = gkr.encryptionPublicKey;
                        } else {
                            r.statusCode = AuthNRequest.ALIAS_UNKNOWN;
                            return;
                        }
                    } else {
                        PGPPublicKey identityPublicKey = keyRing.getPublicKey(c, r.alias, true);
                        r.identityPublicKey = new PublicKey();
                        r.identityPublicKey.setAlias(r.alias);
                        r.identityPublicKey.setFingerprint(Base64.getEncoder().encodeToString(identityPublicKey.getFingerprint()));
                        r.identityPublicKey.setAddress(Base64.getEncoder().encodeToString(identityPublicKey.getEncoded()));
                        r.identityPublicKey.setBase64Encoded(true);
                        r.identityPublicKey.setType("RSA2048");
                        r.identityPublicKey.isEncryptionKey(identityPublicKey.isEncryptionKey());
                        r.identityPublicKey.isIdentityKey(identityPublicKey.isMasterKey());
                        LOG.info("Identity Public Key loaded: " + r.identityPublicKey);

                        PGPPublicKey encryptionPublicKey = keyRing.getPublicKey(c, r.alias, false);
                        r.encryptionPublicKey = new PublicKey();
                        r.encryptionPublicKey.setAlias(r.alias);
                        r.encryptionPublicKey.setFingerprint(Base64.getEncoder().encodeToString(encryptionPublicKey.getFingerprint()));
                        r.encryptionPublicKey.setAddress(Base64.getEncoder().encodeToString(encryptionPublicKey.getEncoded()));
                        r.encryptionPublicKey.setBase64Encoded(true);
                        r.encryptionPublicKey.setType("RSA2048");
                        r.encryptionPublicKey.isEncryptionKey(encryptionPublicKey.isEncryptionKey());
                        r.encryptionPublicKey.isIdentityKey(encryptionPublicKey.isMasterKey());
                        LOG.info("Encryption Public Key loaded: " + r.encryptionPublicKey);
                    }
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_GENERATE_KEY_RINGS: {
                GenerateKeyRingsRequest r = (GenerateKeyRingsRequest)e.getData(GenerateKeyRingsRequest.class);
                if(r == null) {
                    r = new GenerateKeyRingsRequest();
                    r.statusCode = GenerateKeyRingsRequest.REQUEST_REQUIRED;
                    break;
                }
                File f;
                if(r.location == null || r.location.isEmpty()) {
                    // Set locally
                    f = getServiceDirectory();
                    r.location = f.getAbsolutePath();
                } else {
                    f = new File(r.location);
                }
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = GenerateKeyRingsRequest.KEYRING_LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.keyRingUsername == null || r.keyRingUsername.isEmpty()) {
                    r.statusCode = GenerateKeyRingsRequest.KEYRING_USERNAME_REQUIRED;
                    break;
                }
                if(r.keyRingPassphrase == null || r.keyRingPassphrase.isEmpty()) {
                    r.statusCode = GenerateKeyRingsRequest.KEYRING_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.alias == null || r.alias.isEmpty()) {
                    r.statusCode = GenerateKeyRingsRequest.ALIAS_REQUIRED;
                    break;
                }
                if(r.aliasPassphrase == null || r.aliasPassphrase.isEmpty()) {
                    r.statusCode = GenerateKeyRingsRequest.ALIAS_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.keyRingImplementation == null)
                    r.keyRingImplementation = OpenPGPKeyRing.class.getName(); // default
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.createKeyRings(r.location, r.keyRingUsername, r.keyRingPassphrase, r.alias, r.aliasPassphrase, r.hashStrength, r.keyRingImplementation);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_ENCRYPT: {
                EncryptRequest r = (EncryptRequest)e.getData(EncryptRequest.class);
                if(r == null) {
                    r = new EncryptRequest();
                    r.statusCode = EncryptRequest.REQUEST_REQUIRED;
                    e.addData(EncryptRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = EncryptRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = EncryptRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.content == null || r.content.getBody() == null || r.content.getBody().length == 0) {
                    r.statusCode = EncryptRequest.CONTENT_TO_ENCRYPT_REQUIRED;
                    break;
                }
                if(r.publicKeyAlias == null) {
                    r.statusCode = EncryptRequest.PUBLIC_KEY_ALIAS_REQUIRED;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = EncryptRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.encrypt(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_DECRYPT: {
                DecryptRequest r = (DecryptRequest)e.getData(DecryptRequest.class);
                if(r == null) {
                    r = new DecryptRequest();
                    r.statusCode = DecryptRequest.REQUEST_REQUIRED;
                    e.addData(DecryptRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = DecryptRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = DecryptRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.decrypt(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_SIGN: {
                SignRequest r = (SignRequest)e.getData(SignRequest.class);
                if(r == null) {
                    r = new SignRequest();
                    r.statusCode = SignRequest.REQUEST_REQUIRED;
                    e.addData(SignRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = SignRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = SignRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.sign(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_VERIFY_SIGNATURE: {
                VerifySignatureRequest r = (VerifySignatureRequest)e.getData(VerifySignatureRequest.class);
                if(r == null) {
                    r = new VerifySignatureRequest();
                    r.statusCode = VerifySignatureRequest.REQUEST_REQUIRED;
                    e.addData(VerifySignatureRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = VerifySignatureRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = VerifySignatureRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.verifySignature(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_ENCRYPT_SYMMETRIC: {
                EncryptSymmetricRequest r = (EncryptSymmetricRequest)e.getData(EncryptSymmetricRequest.class);
                if(r==null) {
                    r = new EncryptSymmetricRequest();
                    r.statusCode = EncryptSymmetricRequest.REQUEST_REQUIRED;
                    e.addData(EncryptSymmetricRequest.class, r);
                    break;
                }
                if(r.content == null || r.content.getBody() == null || r.content.getBody().length == 0) {
                    r.statusCode = EncryptSymmetricRequest.CONTENT_TO_ENCRYPT_REQUIRED;
                    break;
                }
                if(r.content.getEncryptionPassphrase() == null || r.content.getEncryptionPassphrase().isEmpty()) {
                    r.statusCode = EncryptSymmetricRequest.PASSPHRASE_REQUIRED;
                    break;
                }
                try {
                    byte[] key = r.content.getEncryptionPassphrase().getBytes("UTF-8");
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key,16);
                    // Encrypt
                    SecretKey secretKey = new SecretKeySpec(key, "AES");
                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    byte[] iv = new byte[16];
                    SecureRandom random = new SecureRandom();
                    random.nextBytes(iv);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
                    r.content.setBody(aesCipher.doFinal(r.content.getBody()), false, false);
                    r.content.setBody(Base64.getEncoder().encodeToString(r.content.getBody()).getBytes(), false, false);
                    r.content.setBodyBase64Encoded(true);
                    r.content.setBase64EncodedIV(Base64.getEncoder().encodeToString(iv));
                    r.content.setEncrypted(true);
                    r.content.setEncryptionAlgorithm(EncryptionAlgorithm.AES256);
                } catch (UnsupportedEncodingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (NoSuchAlgorithmException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (NoSuchPaddingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidKeyException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidAlgorithmParameterException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (IllegalBlockSizeException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (BadPaddingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                }

                break;
            }
            case OPERATION_DECRYPT_SYMMETRIC: {
                DecryptSymmetricRequest r = (DecryptSymmetricRequest)e.getData(DecryptSymmetricRequest.class);
                if(r==null) {
                    r = new DecryptSymmetricRequest();
                    e.addData(DecryptSymmetricRequest.class, r);
                    r.statusCode = DecryptSymmetricRequest.REQUEST_REQUIRED;
                    break;
                }
                if(r.content == null || r.content.getBody() == null || r.content.getBody().length == 0) {
                    r.statusCode = DecryptSymmetricRequest.ENCRYPTED_CONTENT_REQUIRED;
                    break;
                }
                if(r.content.getEncryptionPassphrase()==null || r.content.getEncryptionPassphrase().isEmpty()) {
                    r.statusCode = DecryptSymmetricRequest.PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.content.getBase64EncodedIV()==null || r.content.getBase64EncodedIV().isEmpty()) {
                    r.statusCode = DecryptSymmetricRequest.IV_REQUIRED;
                    break;
                }
                try {
                    byte[] key = r.content.getEncryptionPassphrase().getBytes("UTF-8");
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key,16);
                    // Encrypt
                    SecretKey secretKey = new SecretKeySpec(key, "AES");
                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    if(r.content.getBodyBase64Encoded()) {
                        r.content.setBody(Base64.getDecoder().decode(r.content.getBody()), false, false);
                        r.content.setBodyBase64Encoded(false);
                    }
                    byte[] iv = Base64.getDecoder().decode(r.content.getBase64EncodedIV());
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    aesCipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
                    r.content.setBody(aesCipher.doFinal(r.content.getBody()), false, false);
                    r.content.setEncrypted(false);
                    r.content.setBase64EncodedIV(null);
                    r.content.setEncryptionAlgorithm(null);
                } catch (UnsupportedEncodingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (NoSuchAlgorithmException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (NoSuchPaddingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidKeyException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidAlgorithmParameterException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (IllegalBlockSizeException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (BadPaddingException e1) {
                    r.statusCode = DecryptSymmetricRequest.BAD_PASSPHRASE;
                    LOG.warning(e1.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_VOUCH: {
                VouchRequest r = (VouchRequest)e.getData(VouchRequest.class);
                if(r.signer==null) {
                    r.statusCode = VouchRequest.SIGNER_REQUIRED;
                    break;
                }
                if(r.signee==null){
                    r.statusCode = VouchRequest.SIGNEE_REQUIRED;
                    break;
                }
                if(r.attributesToSign==null) {
                    r.statusCode = VouchRequest.ATTRIBUTES_REQUIRED;
                    break;
                }
                // TODO: Verify attributes to sign are available attributs
                LOG.warning("VOUCH not yet implemented.");
            }
            case OPERATION_RELOAD: {
                loadKeyRingImplementations();
            }
            default: deadLetter(e);
        }
    }

    private void loadKeyRingImplementations(){
        keyRings.clear();
        KeyRing keyRing;
        if(properties.getProperty("ra.keyring.KeyRings") == null) {
            keyRing = new OpenPGPKeyRing(); // Default
            if(keyRing.init(properties))
                keyRings.put(OpenPGPKeyRing.class.getName(), keyRing);
        } else {
            String[] keyRingStrings = properties.getProperty("ra.keyring.KeyRings").split(",");
            for (String keyRingString : keyRingStrings) {
                try {
                    keyRing = (KeyRing) Class.forName(keyRingString).getConstructor().newInstance();
                    if(keyRing.init(properties))
                        keyRings.put(keyRingString, keyRing);
                } catch (Exception e) {
                    LOG.warning(e.getLocalizedMessage());
                }
            }
        }
    }

    @Override
    public boolean start(Properties p) {
        super.start(p);
        LOG.info("Starting...");
        updateStatus(ServiceStatus.STARTING);

        properties = p;

        // Android apps set SpongyCastle as the default provider
        if(!SystemVersion.isAndroid()) {
            Security.addProvider(new BouncyCastleProvider());
        }

        loadKeyRingImplementations();

        updateStatus(ServiceStatus.RUNNING);
        LOG.info("Started");
        return true;
    }

    @Override
    public boolean shutdown() {
        super.shutdown();
        LOG.info("Shutting down...");
        updateStatus(ServiceStatus.SHUTTING_DOWN);

        updateStatus(ServiceStatus.SHUTDOWN);
        LOG.info("Shutdown");
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        super.gracefulShutdown();
        LOG.info("Gracefully shutting down...");
        updateStatus(ServiceStatus.GRACEFULLY_SHUTTING_DOWN);

        updateStatus(ServiceStatus.GRACEFULLY_SHUTDOWN);
        LOG.info("Gracefully Shutdown");
        return true;
    }

}
