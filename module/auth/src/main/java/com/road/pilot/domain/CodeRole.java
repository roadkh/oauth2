package com.road.pilot.domain;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;

/**
 * Created by road on 16. 12. 5.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@EqualsAndHashCode
@ToString
@Getter
@Entity
@Table(name = "code_role")
public class CodeRole implements Serializable {

    private static final long serialVersionUID = -352185484215960337L;

    @Id
    @Column(name = "id", unique = true, nullable = false, updatable = false, length = 36, columnDefinition = "char(36)")
    private String id;

    @Column(name = "label", nullable = false)
    private String label;

    public CodeRole(String id, String label) {
        this.id = id;
        this.label = label;
    }
}
