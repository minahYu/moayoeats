package com.moayo.moayoeats.backend.domain.order.repository;

import com.moayo.moayoeats.backend.domain.order.entity.Order;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<Order,Long> {

}
