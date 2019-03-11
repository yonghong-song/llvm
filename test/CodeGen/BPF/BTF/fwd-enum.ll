; RUN: llc -march=bpfel -filetype=asm -o - %s | FileCheck -check-prefixes=CHECK %s
; RUN: llc -march=bpfeb -filetype=asm -o - %s | FileCheck -check-prefixes=CHECK %s

; Source code:
;   enum A;
;   int foo(enum A *a) { return 0; }
; Compilation flag:
;   clang -target bpf -O2 -g -S -emit-llvm t.c

; Function Attrs: nounwind readnone
define dso_local i32 @foo(i32* nocapture readnone) local_unnamed_addr #0 !dbg !7 {
  call void @llvm.dbg.value(metadata i32* %0, metadata !14, metadata !DIExpression()), !dbg !15
  ret i32 0, !dbg !16
}

; CHECK:             .section        .BTF,"",@progbits
; CHECK-NEXT:        .short  60319                   # 0xeb9f
; CHECK-NEXT:        .byte   1
; CHECK-NEXT:        .byte   0
; CHECK-NEXT:        .long   24
; CHECK-NEXT:        .long   0
; CHECK-NEXT:        .long   72
; CHECK-NEXT:        .long   72
; CHECK-NEXT:        .long   49
; CHECK-NEXT:        .long   0                       # BTF_KIND_PTR(id = 1)
; CHECK-NEXT:        .long   33554432                # 0x2000000
; CHECK-NEXT:        .long   2
; CHECK-NEXT:        .long   37                      # BTF_KIND_FWD(id = 2)
; CHECK-NEXT:        .long   1191182336              # 0x47000000
; CHECK-NEXT:        .long   0
; CHECK-NEXT:        .long   0                       # BTF_KIND_FUNC_PROTO(id = 3)
; CHECK-NEXT:        .long   218103809               # 0xd000001
; CHECK-NEXT:        .long   4
; CHECK-NEXT:        .long   39
; CHECK-NEXT:        .long   1
; CHECK-NEXT:        .long   41                      # BTF_KIND_INT(id = 4)
; CHECK-NEXT:        .long   16777216                # 0x1000000
; CHECK-NEXT:        .long   4
; CHECK-NEXT:        .long   16777248                # 0x1000020
; CHECK-NEXT:        .long   45                      # BTF_KIND_FUNC(id = 5)
; CHECK-NEXT:        .long   201326592               # 0xc000000
; CHECK-NEXT:        .long   3
; CHECK-NEXT:        .byte   0                       # string offset=0
; CHECK-NEXT:        .ascii  ".text"                 # string offset=1
; CHECK-NEXT:        .byte   0
; CHECK-NEXT:        .ascii  "/home/yhs/tests/llvm/enum/t.c" # string offset=7
; CHECK-NEXT:        .byte   0
; CHECK-NEXT:        .byte   65                      # string offset=37
; CHECK-NEXT:        .byte   0
; CHECK-NEXT:        .byte   97                      # string offset=39
; CHECK-NEXT:        .byte   0
; CHECK-NEXT:        .ascii  "int"                   # string offset=41
; CHECK-NEXT:        .byte   0
; CHECK-NEXT:        .ascii  "foo"                   # string offset=45
; CHECK-NEXT:        .byte   0

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

attributes #0 = { nounwind readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4, !5}
!llvm.ident = !{!6}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 8.0.20181009 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, nameTableKind: None)
!1 = !DIFile(filename: "t.c", directory: "/home/yhs/tests/llvm/enum")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{i32 1, !"wchar_size", i32 4}
!6 = !{!"clang version 8.0.20181009 "}
!7 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 2, type: !8, isLocal: false, isDefinition: true, scopeLine: 2, flags: DIFlagPrototyped, isOptimized: true, unit: !0, retainedNodes: !13)
!8 = !DISubroutineType(types: !9)
!9 = !{!10, !11}
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 64)
!12 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "A", file: !1, line: 1, flags: DIFlagFwdDecl)
!13 = !{!14}
!14 = !DILocalVariable(name: "a", arg: 1, scope: !7, file: !1, line: 2, type: !11)
!15 = !DILocation(line: 2, column: 17, scope: !7)
!16 = !DILocation(line: 2, column: 22, scope: !7)
