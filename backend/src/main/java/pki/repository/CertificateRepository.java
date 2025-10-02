package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.Certificate;
import pki.model.CertificateParty;
import pki.model.CertificateType;
import pki.model.Organization;

import java.util.List;

public interface CertificateRepository extends JpaRepository<Certificate,String> {
    List<Certificate> findBySubject(CertificateParty subject);
    Certificate findFirstBySubject(CertificateParty subject);
    List<Certificate> findByTypeIn(List<CertificateType> types);
    Certificate findFirstBySerialNumber(String serialNumber);
    Certificate findFirstByType(CertificateType type);
    List<Certificate> findByIssuer_Organization(Organization organization);
}
