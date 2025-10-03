package pki.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.keycloak.exportimport.Strategy;

import java.security.PrivateKey;
import java.security.PublicKey;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class CertificateParty {
    @Id
    private String id;
    private String commonName;
    private String surname;
    private String givenName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;
    private String alternativeName;

    public X500Name getX500Name(){
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.UID, id);
        if (commonName != null) {
            builder.addRDN(BCStyle.CN, commonName);
        }
        if (surname != null) {
            builder.addRDN(BCStyle.SURNAME, surname);
        }
        if (givenName != null) {
            builder.addRDN(BCStyle.GIVENNAME, givenName);
        }
        if (organization != null) {
            builder.addRDN(BCStyle.O, organization);
        }
        if (organizationalUnit != null) {
            builder.addRDN(BCStyle.OU, organizationalUnit);
        }
        if (country != null) {
            builder.addRDN(BCStyle.C, country);
        }
        if (email != null) {
            builder.addRDN(BCStyle.E, email);
        }
        return builder.build();
    }
}

