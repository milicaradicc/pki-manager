package pki.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.bouncycastle.asn1.x509.CRLReason;

public enum RevocationReason {
    UNSPECIFIED(CRLReason.unspecified),
    KEY_COMPROMISE(CRLReason.keyCompromise),
    CA_COMPROMISE(CRLReason.cACompromise),
    AFFILIATION_CHANGED(CRLReason.affiliationChanged),
    SUPERSEDED(CRLReason.superseded),
    CESSATION_OF_OPERATION(CRLReason.cessationOfOperation),
    CERTIFICATE_HOLD(CRLReason.certificateHold),
    REMOVE_FROM_CRL(CRLReason.removeFromCRL),
    PRIVILEGE_WITHDRAWN(CRLReason.privilegeWithdrawn),
    AA_COMPROMISE(CRLReason.aACompromise);

    private final int code;

    RevocationReason(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public CRLReason toBouncyCastleCRLReason() {
        return CRLReason.lookup(code);
    }

    @JsonCreator
    public static RevocationReason fromString(String value) {
        return RevocationReason.valueOf(value.toUpperCase());
    }

    @JsonValue
    public String toValue() {
        return this.name();
    }
}
