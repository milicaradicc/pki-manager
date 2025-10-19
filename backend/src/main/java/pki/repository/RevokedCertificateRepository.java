package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pki.model.RevokedCertificate;

import java.util.List;

@Repository
public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, String> {
    List<RevokedCertificate> findByIssuerId(String issuerId);
    boolean existsBySerialNumber(String serialNumber);
    RevokedCertificate findBySerialNumber(String serialNumber);
}