package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.RevokedCertificate;

import java.util.List;

public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, String> {
    boolean existsBySerialNumber(String serialNumber);
    List<RevokedCertificate> findByIssuerId(String issuerId);
}
