package com.road.pilot.repository;

import com.road.pilot.domain.User;
import org.springframework.data.repository.CrudRepository;

/**
 * Created by road on 16. 12. 12.
 */
public interface UserRepository extends CrudRepository<User, String> {

    User findByEmail(String email);
}
