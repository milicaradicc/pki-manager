package pki.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Entity
@Table(name = "USER_")
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true)
    private String keycloakId;

    @Column(unique = true)
    private String email;

    @Column
    private String firstname;

    @Column
    private String lastname;

    @Column
    private String organization;

    @ManyToMany(fetch = FetchType.EAGER)
    private List<Certificate> ownedCertificates;
}
