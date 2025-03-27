; util.asm
;
; esc 7 -> save current cursor pos
; esc 8 -> restore saved cursor pos
;

%define _custom_source
%include "util.asmh"
bits 32

section .data3 write exec   ; @REM
    ansicode:
        .arg0               db 0x1b,'['
                            db 'm',0x00
        .arg1               db 0x1b,'['
        .arg101             db 0x00,0x00
                            db 'm',0x00
        .arg2               db 0x1b,'['
        .arg201             db 0x00,0x00
                            db ';'
        .arg202             db 0x00,0x00
                            db 'H',0x00


    lf                      db 0x0a,0x00
    star                    db '*',0x00
    tty:
        istruc termios
            at .c_iflag,     dd 0x00
            at .c_oflag,     dd 0x00
            at .c_cflag,     dd 0x00
            at .c_lflag,     dd 0x00
            at .c_line,      db 0x00
            at .c_cc,        db 0x00
        iend
    state:
        ; istruc pwstate
        ;     at .cur,         times 0x20 db 0x00
        ;     at .old,         times 0x20 db 0x00
        ;     at .password,    times 0x20 db 0x00
        ;     at .buf,         db 0x00,0x00
        ;     at .length,      db 0x00
        ; iend
         istruc pwstate
            at .cur,         dd 0x00,0x00,0x00,0x00,0x00 
            at .old,         dd 0x00,0x00,0x00,0x00,0x00 
            at .password,    dd 0x00,0x00,0x00,0x00,0x00 
            at .buf,         db 0x00,0x00
            at .length,      db 0x00
        iend
    prompt                   db "Password: ", 0x00

;   getpw :: String
    getpw:
            head
            echooff tty
            mov eax,prompt
            push eax
            print
            ansi 0,1

            ; read 1 byte
            pop eax
            mov [gs8],eax
            pop eax
            mov eax,(state+pwstate.buf)
            mov [gsc],eax
            push eax
            xor eax,eax
            mov byte [gs6],al
        .go:
            call readone

            ; copy to struct
            mov eax,(state+pwstate.buf)
            xor ebx,ebx
            mov byte bl,[eax]
            cmp byte bl,0x0a
            je .end

            mov ecx,(state+pwstate.length)
            xor edx,edx
            mov byte dl,[ecx]
            mov eax,(state+pwstate.password)
            add eax,edx
            xor ecx,ecx
            mov byte [eax],bl
            inc byte dl
            mov ecx,(state+pwstate.length)
            mov byte [ecx],dl
            inc byte [gs6]
            cmp byte [gs6],0x20
            je .end

            ; print a star
            mov eax,star
            push eax
            print
            mov eax,[gsc]
            push eax
            jmp .go

        .end:
            ansi 0,0
            printonlyln

            echoon tty
            mov eax,(state+pwstate.password)
            tail
            ret


;   sys_ioctl :: Pointer t => Int -> Int -> Struct Termios t -> Int
    sys_ioctl:
            head
            mov eax,0x36
            pop ebx
            pop ecx
            pop edx
            int 0x80

            tail
            ret

;   fail :: Never
    fail:
            head
            print
            push 0x01
            call exit

            tail
            ret

;   strlen :: String -> Int
    strlen:
            head esi,edx
            pop ebx
            ; mov edx,ebx
            xor eax,eax
            xor ecx,ecx
        .loop:
            mov cl,[ebx]
            cmp cl,0x00
            je .end
            inc ebx
            inc eax
            jmp .loop
        .end:
            ; push edx
            sub esp,0x04
            tail esi,edx
            ret

;   readone :: String -> Int
    readone:
            head
            mov eax,0x03
            mov ebx,0x00
            pop ecx
            mov byte [ecx],0x00
            mov byte [ecx+1],0x00
            mov edx,0x01
            jmp read.interrupt
            nop

;   read :: Int -> String -> Int -> Int
    read:
            head
            mov eax,0x03
            pop ebx
            pop ecx
            pop edx
        .interrupt:
            int 0x80

            tail
            ret

;   sys_write_n :: String -> Int -> Int
    sys_write_n:
            head esi,ebp
            pop ecx
            pop edx
            mov ebx,0x01
            mov eax,0x04
            int 0x80

            tail esi,ebp
            ret

;   sys_write :: String -> Int
    sys_write:
            head esi,ebp
            call strlen
            mov edx,eax

            pop ecx
            mov ebx,0x01
            mov eax,0x04
            int 0x80

            tail esi,ebp
            ret

;   write :: Int -> String -> Int -> Int
    write:
            head
            mov eax,0x04
            pop ebx
            pop ecx
            pop edx
            int 0x80
            tail
            ret
    
;   exit :: Int -> Never
    exit:
            head
            mov eax,0x01
            pop ebx
            int 0x80

            tail
            ret

;   resetterm :: ()
    resetterm:
            head
            ansi 0,0
            tail
            ret

;   open :: Flags f => String -> f -> Int
    open:
            head
            mov eax,0x05
            pop ebx
            pop ecx
            int 0x80
            tail
            ret

;   memfd_create :: Flags f => String -> f -> Int
    memfd_create:
            head
            mov eax,0x0164
            pop ebx
            pop ecx
            int 0x80
            tail
            ret

;   execveat :: Flags f => Int -> String -> [String]
;                   -> [String] -> f -> Int
    execveat:
            head
            mov eax,0x0166
            pop ebx
            pop ecx
            pop edx
            pop esi
            pop edi
            int 0x80
            tail
            ret

    stack:
            times 0x20 dd 0x00

    endaddr:

    ; base    equ 0x07000000 
    ; code    equ (base+0x78)
    ; cipher  equ (base+codesz)
    ; salt    equ cipher
    ; memsz   equ (base+0x68)
    memsz   equ (base+0x68)
    padding equ 0x10000
    word16  equ 0x02

    gsvars ; @REM
