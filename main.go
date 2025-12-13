package main

import (
	"disASMfunc/pkg/analyzer"
	"disASMfunc/pkg/processor"
	"disASMfunc/pkg/syscalls"
	"fmt"
	"log"
)

func main() {
	const LibcPath = "./libc.so.6"
	fmt.Printf("Glibc 라이브러리 분석 중: %s\n", LibcPath)

	// 1. Libc 분석기 초기화
	libcAnalyzer, err := analyzer.New(LibcPath)
	if err != nil {
		log.Fatalf("Libc 분석기 생성 오류: %v", err)
	}
	defer libcAnalyzer.Close()

	fmt.Println("--- 매핑 테스트 시작 (모든 정의된 커널 시스템 콜) ---")

	// 2. 정의된 모든 커널 시스템 콜 이름(예: read, write)을 순회하며 테스트
	for _, syscallName := range syscalls.KernelSyscallNameMap {

		// BuildSyscallMap은 map[string]struct{} 형태를 기대합니다.
		wrapperTestSet := map[string]struct{}{
			syscallName: {},
		}

		// 3. 매핑 로직 호출
		redisMap := processor.BuildSyscallMap(libcAnalyzer, wrapperTestSet)

		// 4. 결과 출력
		if kernelSyscall, ok := redisMap[syscallName]; ok {
			// 성공한 경우, processor.go 내부에서 이미 상세 로그를 출력합니다.
			fmt.Printf("  [성공] %s (래퍼) -> %s (커널)\n", syscallName, kernelSyscall)
		} else {
			// 실패한 경우, 이전에 기억하시는 '매칭실패' 메시지를 출력합니다.
			fmt.Printf("  [실패] %s (래퍼) -> 매핑 실패 (심볼 없음/syscall 명령어 없음)\n", syscallName)
		}
	}
	fmt.Println("--- 매핑 테스트 완료 ---")
}
