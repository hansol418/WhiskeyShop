package com.busanit501.boot501.security;

import com.busanit501.boot501.domain.Member;
import com.busanit501.boot501.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Log4j2
@RequiredArgsConstructor
public class APIUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username = mid 로 사용
        Optional<Member> result = memberRepository.findByMid(username);
        Member member = result.orElseThrow(() -> new UsernameNotFoundException("Cannot find member: " + username));

        log.info("APIUserDetailsService - member: {}", member.getMid());

        // Member.roleSet -> GrantedAuthority 로 변환
        var authorities = member.getRoleSet().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toList());

        // Spring Security 기본 User 로 반환 (UserDetails 구현체)
        return User.builder()
                .username(member.getMid())
                .password(member.getMpw())   // 이미 암호화되어 있어야 함
                .authorities(authorities)
                .accountLocked(false)
                .disabled(member.isDel())    // del=true 를 비활성 처리로 활용 가능 (필요 시)
                .build();
    }
}
