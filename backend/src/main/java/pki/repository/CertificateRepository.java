package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.Certificate;
import pki.model.CertificateParty;
import pki.model.CertificateType;

import java.util.List;

public interface CertificateRepository extends JpaRepository<Certificate,String> {
    List<Certificate> findBySubject(CertificateParty subject);
    List<Certificate> findByTypeIn(List<CertificateType> types);
    Certificate findFirstBySerialNumber(String serialNumber);
}
