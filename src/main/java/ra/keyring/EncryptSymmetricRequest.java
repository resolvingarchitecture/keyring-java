package ra.keyring;

import ra.common.content.Content;

/**
 * Request:
 * @see Content
 *
 * Response
 * @see Content
 *
 */
public class EncryptSymmetricRequest extends KeyRingsRequest {
    public static int CONTENT_TO_ENCRYPT_REQUIRED = 2;
    public static int PASSPHRASE_REQUIRED = 3;

    public Content content;
}
