package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import pki.model.Organization;

import java.util.Optional;

public interface OrganizationRepository extends JpaRepository<Organization,Integer> {
    @Query("SELECT o FROM Organization o WHERE LOWER(o.name) = LOWER(:name)")
    Optional<Organization> findByNameCaseInsensitive(String name);
    boolean existsByName(String name);
}
