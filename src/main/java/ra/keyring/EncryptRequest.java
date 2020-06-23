package ra.keyring;

import ra.common.content.Content;

/**
 * Request:
 * String Key Ring Username
 * String Key Ring Passphrase
 * String Public Key Alias you wish to use for Encryption
 * @see Content
 *
 * Response:
 * @see Content
 *
 */

public class EncryptRequest extends KeyRingsRequest {
    public static int CONTENT_TO_ENCRYPT_REQUIRED = 2;
    public static int PUBLIC_KEY_ALIAS_REQUIRED = 3;
    public static int PUBLIC_KEY_NOT_FOUND = 4;
    public static int LOCATION_REQUIRED = 5;
    public static int LOCATION_INACCESSIBLE = 6;

    public String location;
    public String keyRingUsername;
    public String keyRingPassphrase;
    public String publicKeyAlias;
    public Content content;
    public Boolean passphraseOnly = false;
}
