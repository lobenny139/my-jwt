package com.my.jwt.service;

import com.my.db.entity.Member;
import com.my.db.service.IMemberService;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Getter
@Service
public class JwtUserDetailsService implements UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailsService.class);

	@Autowired(required=true)
	@Qualifier("memberService")
	private IMemberService service;

	@Autowired
	private PasswordEncoder bcryptEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.info("開始驗証[{}]", username);
		Member member = getService().getEntityByAccount( username );
		if (member == null) {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}
		logger.info("結束驗証[{}]", username);
		return new org.springframework.security.core.userdetails.User(member.getAccount(), member.getPassword(),
				new ArrayList<>());
	}

}