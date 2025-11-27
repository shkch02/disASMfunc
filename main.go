package main

import (
	"disASMfunc/pkg/analyzer"
	"disASMfunc/pkg/processor"
	"fmt"
	"log"
)

func main() {
	const LibcPath = "./libc.so.6"
	fmt.Printf("Glibc 라이브러리 분석 중: %s\n", LibcPath)
	libcAnalyzer, err := analyzer.New(LibcPath)
	if err != nil {
		log.Fatalf("Libc 분석기 생성 오류: %v", err)
	}
	defer libcAnalyzer.Close()

	// disASMfunc에서 쓰려고 대문자로 바꿈, 원래 분석기에선 소문자임
	//for i, uniqueWrappers := range syscalls.KernelSyscallNameMap { //키값인 넘버는 _로 무시
	//	fmt.Printf("%d Syscall name: %s\n", i, uniqueWrappers)
	//}

	//for _, syscalls := range syscalls.KernelSyscallNameMap { //2:open
	//map[string]struct{}{syscalls: {}}

	uniqueWrappers := map[string]struct{}{
		"2:open": {},
	}

	/*redisMap :=*/
	processor.BuildSyscallMap(libcAnalyzer, uniqueWrappers) //라이브러리 바이너리, 시스템콜 문자열 추출 not a map
	//fmt.Println(redisMap)

	//}
	fmt.Println("objdump -d ./libc.so.6 | grep 시스템콜 ")
}
