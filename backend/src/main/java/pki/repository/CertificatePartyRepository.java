package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.CertificateParty;

public interface CertificatePartyRepository extends JpaRepository<CertificateParty, String> {
}
