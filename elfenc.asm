;org 0x07000078

; Try increasing, one at the time
;   if you get "wrong password"
;   when you shouldn't (max: 4)
%define nalign 2


; start of code
beginaddr:

%include "util.asmh"
bits 32
align 4
global _start
; global main

extern hash         ; @REM
extern ksa          ; @REM
extern prgainit     ; @REM
extern whitewash    ; @REM
extern prga         ; @REM
extern kdf          ; @REM

; org code
section .text nowrite exec  ; @REM
;   _start :: Int -> [String] -> Int
    ; _start:
    ; main:
            mov esp,stack
            mov ebp,esp
            signal sigint

    getcprsize:
            mov ebx,memsz
            mov eax,[ebx]
        ;     sub eax,0x04
        ; add eax,padding
            mov ebx,cprsize
            mov [ebx],eax
        
; main:
_start:
    getcodesize:
            mov eax,endaddr
            mov ebx,beginaddr
            sub eax,ebx
            inc eax
            mov ebx,codesz
            mov [ebx],eax

    getsaltaddr:
            ; mov ebx,base
            mov ebx,code
            add eax,ebx
            mov ebx,salt
            mov [ebx],eax

    getpassword:
           call getpw
            mov ebx,pw
            mov [ebx],eax

    getlength:
            push eax
            call strlen
            mov ebx,pwsize
            mov [ebx],ax

    checklength:
            cmp ax,0x00
            jz end

    hashing:
            mov ebx,pwsize
            mov eax,[ebx]
            push eax

            mov ebx,salt
            mov eax,[ebx]
            push eax

            mov ebx,pw
            mov eax,[ebx]
            push eax

            mov eax,uhash
            push eax

            call hash

    checkhashing:
            cmp eax,0x00
            jz end

    derivekey:
            mov ebx,pwsize
            mov eax,[ebx]
            push eax

            mov ebx,salt
            mov eax,[ebx]
            push eax

            mov ebx,pw
            mov eax,[ebx]
            push eax
            call kdf

            mov ebx,key
            mov [ebx],eax

    initcrypto:
            push eax
            mov eax,state
            push eax
            call ksa

            mov eax,state
            push eax
            call prgainit

            mov eax,state
            push eax
            call whitewash

    decrypt:
        .init:
            mov ebx,salt
            mov eax,[ebx]
            add eax,0x04
            mov edi,eax     ; cipher

            mov ebx,cprsize
            mov ecx,[ebx]

        .loop:
            cmp ecx,0x00
            jz .end

            mov ebx,counter
            mov [ebx],ecx
            mov ebx,pointer
            mov [ebx],edi

            mov eax,state
            push eax
            call prga

            mov ebx,counter
            mov ecx,[ebx]
            mov ebx,pointer
            mov edi,[ebx]

            xor ebx,ebx
            mov byte bl,[edi]
            xor al,bl
            mov byte [edi],al

            dec ecx ; 0x70001a5
            inc edi
            jmp .loop

        .end:
            nop

    pad:
            mov eax,salt
            mov ebx,[eax]
            add ebx,0x04

            xor eax,eax
            mov word ax,[ebx]
            mov edx,padding
            sub edx,0x14
            cmp dx,ax
            jg .reduce

            add eax,ebx
            jmp cmphashes

        .reduce:
            mov ax,dx
            add eax,ebx

    cmphashes:
            mov edi,uhash
            mov esi,eax
            mov ecx,0x14
            repne cmpsb
            jz .equal

        .ne:
            mov eax,badpw
            push eax
            print
            jmp end

        .equal:
            nop

    openfd:
             xor ecx,ecx
             or ecx,mfd_cloexec
        ;      xor eax,eax
        ;     or eax,mfd_cloexec
        ;     push eax
        ;     mov eax,elfenc
        ;     push eax
        ;     call memfd_create
            mov eax,0x0164
            mov ebx,elfenc
            int 0x80

            mov esi,eax
        ;     cmp eax,0x01
        ;     jge end
        ;   cmp eax,0xffffffff
        ;   je end
        nop

    writefd:
            nop

        .init:
            mov ebx,salt
            mov ecx,[ebx]
            add ecx,0x06
            add ecx,padding
            mov edi,ecx

            mov ebx,cprsize
            mov ecx,[ebx]
            sub ecx,word16
            sub ecx,padding
            add ecx,0x04

        .loop:
            mov eax,bufsize
            push eax
            mov eax,edi
            push eax
            mov eax,esi
            push eax

            ; esi = memfd
            ; edi = ptr
            ; ecx = counter
            mov eax,pointer
            mov [eax],edi
            call write
        ;     cmp eax,bufsize
        ;     jne .error
            
            mov ebx,pointer
            mov edi,[ebx]
            add edi,bufsize
            sub ecx,bufsize
            cmp eax,bufsize
            je .loop
            jmp .end
%if nalign == 1
            nop
%elif nalign == 2
    times 2 nop
%elif nalign == 3
    times 3 nop
%elif nalign > 3
    times 4 nop
%endif
        .lastwrite:
            push ecx
            mov eax,edi
            push eax
            mov eax,esi
            push eax

            call write
            cmp eax,ecx
            je .end
            nop
            nop

        .error:
            mov eax,0x06
            mov ebx,esi
            int 0x80
            jmp end

        .end:
            nop

    EXECUTE:
    _EXECUTE:
    __EXECUTE:
    ___EXECUTE:
;   @@@ EXECUTE G'DMNIT! @@@
                ; mov eax,at_empty_path
                ; push eax
                ; mov eax,env
                ; push eax
                ; mov eax,arg
                ; push eax
                ; mov eax,null
                ; push eax
                ; mov eax,esi
                ; push eax

            mov eax,0x0166
            mov ebx,esi
            mov ecx,null
            mov edx,arg
            mov esi,env
            mov edi,at_empty_path

                ; mov eax,0x0166
                ; mov ebx,at_empty_path
                ; mov ecx,env
                ; mov edx,arg
                ; mov edi,esi
                ; mov esi,null

                ; yeees!
                ; call execveat
                int 0x80

            .cleanup:
                mov eax,0x06
                mov ebx,esi
                int 0x80

    end:
            call resetterm
            mov eax,0x01
            push eax
            call exit
            ret

    unreachable:
            nop
            jmp unreachable

    sigint:
            call resetterm
            mov eax,0x01
            push eax
            call exit
    
section .data12 write noexec    ; @REM
    buf     resb 0x40
;     bufsize equ ($-buf)
bufsize equ 0x01
    pw      resd 0x01
    pwsize  resw 0x01
    key     resd 0x01
    state   resb 0x0166
    uhash   resb 0x14
    cprsize resd 0x01
    counter resd 0x01
    pointer resd 0x01

section .data12 write noexec    ; @REM
    badpw   db "Error: bad password",0x0a,0x00
    elfenc db "elfenc",0x00
    arg     dd elfenc,0x00
    null    dd 0x00
    env     dd null,0x00
    codesz  dd 0x00
    salt    dd 0x00

    memsz   equ (base+0x68) ; @REM
    padding equ 0x10000     ; @REM
    word16  equ 0x02        ; @REM
    endaddr:                ; @REM

            gsvars
