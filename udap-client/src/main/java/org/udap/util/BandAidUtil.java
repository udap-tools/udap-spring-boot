package org.udap.util;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Place holder for temporary code or fixes to account for scenarios where objects need
 * tweaking for one-reason or another.
 *
 * @author Brett P. Stringham
 *
 */
public class BandAidUtil {

    /**
     * Assumes all RSAKey - drops kid attribute from JWKs in JWKSet
     * @param jwkSet
     * @return
     */
    public static JWKSet dropKidFromJwkSet(JWKSet jwkSet) {
        for (JWK jwk : jwkSet.getKeys()) {
            if (jwk instanceof RSAKey) {
                RSAKey.Builder builder = new RSAKey.Builder((RSAKey)jwk).keyID(null);
                return new JWKSet(builder.build());
            }
        }
        return null;

    }

}
