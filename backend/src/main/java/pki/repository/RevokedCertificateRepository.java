package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.RevokedCertificate;

public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, String> {
    boolean existsBySerialNumber(String serialNumber);
}
