package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.Certificate;

public interface CertificateRepository extends JpaRepository<Certificate,String> {
}
