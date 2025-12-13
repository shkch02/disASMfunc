package main

import (
	"disASMfunc/pkg/analyzer"
	"disASMfunc/pkg/processor"
	"disASMfunc/pkg/syscalls"
	"fmt"
	"log"
	"strings" // 새로 추가: 결과를 쉼표로 연결하기 위해 사용
)

func main() {
	const LibcPath = "./libc.so.6"
	fmt.Printf("Glibc 라이브러리 분석 중: %s\n", LibcPath)

	libcAnalyzer, err := analyzer.New(LibcPath)
	if err != nil {
		log.Fatalf("Libc 분석기 생성 오류: %v", err)
	}
	defer libcAnalyzer.Close()

	// 결과를 저장할 슬라이스 선언
	var successfulSyscalls []string
	var failedSyscalls []string

	fmt.Println("--- 매핑 테스트 시작 (모든 정의된 커널 시스템 콜) ---")

	// 정의된 모든 커널 시스템 콜 이름(Wrapper로 가정)을 순회하며 테스트
	// (syscalls.KernelSyscallNameMap 사용)
	for _, syscallName := range syscalls.KernelSyscallNameMap {

		// BuildSyscallMap이 요구하는 map[string]struct{} 형태의 인자를 전달
		wrapperTestSet := map[string]struct{}{
			syscallName: {},
		}

		// 매핑 로직 호출 (processor.BuildSyscallMap)
		// 참고: BuildSyscallMap 내부에서 디버깅을 위한 상세 로그가 출력됩니다.
		redisMap := processor.BuildSyscallMap(libcAnalyzer, wrapperTestSet)

		// 결과 분류
		if _, ok := redisMap[syscallName]; ok {
			// 매핑 성공 (Tracepoint 필터링까지 통과)
			successfulSyscalls = append(successfulSyscalls, syscallName)
		} else {
			// 매핑 실패 (심볼 없음, syscall 명령어 없음, 또는 Tracepoint 없음)
			failedSyscalls = append(failedSyscalls, syscallName)
		}
	}

	fmt.Println("--- 매핑 테스트 완료 ---")
	fmt.Println("========================================")

	// 최종 결과 출력 (성공 목록)
	fmt.Printf("✅ 성공한 시스템콜 (%d개):\n", len(successfulSyscalls))
	fmt.Printf("%s\n", strings.Join(successfulSyscalls, ", "))

	// 최종 결과 출력 (실패 목록)
	fmt.Println("\n❌ 실패한 시스템콜:")
	fmt.Printf("실패한 시스템콜 (%d개):\n", len(failedSyscalls))
	fmt.Printf("%s\n", strings.Join(failedSyscalls, ", "))
	fmt.Println("========================================")
}
