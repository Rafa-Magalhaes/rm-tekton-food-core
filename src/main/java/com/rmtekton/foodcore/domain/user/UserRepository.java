package com.rmtekton.foodcore.domain.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmail(String email);

    Optional<User> findByEmailAndActiveTrue(String email);

    Optional<User> findByIdAndActiveTrue(UUID id);
}