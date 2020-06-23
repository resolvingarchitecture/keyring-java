package ra.keyring;

import ra.common.ServiceMessage;

/**
 * TODO: Add Description
 */
public abstract class KeyRingsRequest extends ServiceMessage {
    public static int KEY_RING_IMPLEMENTATION_UNKNOWN = 1;

    public String keyRingImplementation = "ra.keyring.OpenPGPKeyRing"; // default
}
