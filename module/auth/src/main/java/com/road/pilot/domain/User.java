package com.road.pilot.domain;

import lombok.*;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.util.StringUtils;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by road on 16. 12. 12.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@EqualsAndHashCode
@ToString
@Getter
@Entity
@Table(name = "User")
public class User implements Serializable {
    private static final long serialVersionUID = 4978746543808434829L;

    @Id
    @GeneratedValue(generator = "uuid")
    @GenericGenerator(name="uuid", strategy = "uuid2")
    @Column(name = "id", length = 36, columnDefinition = "char(36)")
    private String id;

    @Column(name = "email", unique = true, nullable = false)
    private String email;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "password", nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.REFRESH)
    @JoinTable(
            name = "user_role",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id" )
    )
    private Set<CodeRole> roles = new HashSet<>();

    public User(String email, String name, String password, String roles) {
        this.email = email;
        this.name = name;
        this.password = password;
        if(roles != null && !roles.isEmpty()) {
            Set<String> roleSet = StringUtils.commaDelimitedListToSet(roles);
            for(String role : roleSet) {
                role = role.trim();
                this.roles.add(new CodeRole(role, ""));
            }
        }
    }

}
