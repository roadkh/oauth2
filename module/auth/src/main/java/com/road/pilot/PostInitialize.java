package com.road.pilot;

import com.road.pilot.domain.CodeRole;
import com.road.pilot.domain.User;
import com.road.pilot.repository.CodeRoleRepository;
import com.road.pilot.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by road on 16. 12. 12.
 */
@Component
public class PostInitialize implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CodeRoleRepository codeRoleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        Set<CodeRole> roles = new HashSet<>();
        CodeRole role1 = new CodeRole("ROLE_USER", "User");
        CodeRole role2 = new CodeRole("ROLE_ADMIN", "Admin");
        CodeRole role3 = new CodeRole("ROLE_HOST", "Host");
        roles.add(role1);
        roles.add(role2);
        roles.add(role3);
        codeRoleRepository.save(roles);

        User user = new User("roadkh@gmail.com", "road kim", passwordEncoder.encode("2222"), "ROLE_USER");
        userRepository.save(user);
    }
}
