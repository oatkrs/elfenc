; arcfour.asm
%include "util.asmh"
bits 32
global ksa
global prgainit
global whitewash
global prga

section .data4 write exec   ; @REM
    keylen      equ 0x10

    ; for each state:
    ;
    ; s:      resb 0x100
    ;     .i  resb 0x01
    ;     .j  resb 0x01
    ;

;   ksa :: State s => s -> String -> s
    ksa:
            head
            mov [gs8],esi
            ; pop eax
            ; mov ebx,[eax]
            pop ebx
            pop eax
            ; mov esi,[eax]
            mov esi,eax

    ksainit:
            xor ecx,ecx
        
        .loop:
            cmp ecx,0x100
            je .done
            mov eax,ecx
            add eax,ebx
            mov [eax],cl
            inc ecx
            jmp .loop

        .done:
            nop

    schedule:
            xor ecx,ecx
            xor edi,edi
            
        .loop:
            cmp ecx,0x100
            je .done

            mov eax,keylen
            test ecx,0x00
            jnz .modulo
            xor eax,eax
            jmp .surpass

        .modulo:
            mod eax,ecx

        .surpass:
            add eax,esi
            xor edx,edx
            mov dl,[eax]
            push edx
            mov eax,ecx
            add eax,ebx
            xor edx,edx
            mov dl,[eax]
            push edx
            mov eax,edi
            pop edx
            add eax,edx
            pop edx
            add eax,edx
            push ecx
            mov ecx,eax
            ; mov edx,eax
            mov eax,0x100
            ; mod eax,edx
            ; -- mod eax,ecx
            pop ecx
            add eax,edi
            xor edx,edx
            mov byte dl,al
            mov edi,edx
            ; mov edi,eax

            ; ebx = s
            ; esi = key
            ; edi = j
            mov eax,ecx
            add eax,ebx
            mov edx,[eax]
            push edx

            mov eax,edi
            add eax,ebx
            mov edx,[eax]
            push edx

            mov eax,ecx
            add eax,ebx
            pop edx
            mov [eax],edx

            mov eax,edi
            add eax,ebx
            pop edx
            mov [eax],edx

            inc ecx
            jmp .loop

        .done:
            mov eax,ebx
            mov esi,[gs8]
            ; push eax
            ; push eax
            tail
            ret


    %define S   [gs0]
    %define ESI [gs4]
;   prgainit :: State s => s -> ()
    prgainit:
            head
            mov ESI,esi
            pop eax
            mov S,eax

            mov edx,S
            mov esi,edx
            add esi,0x100
            mov edi,esi
            inc edi
            xor eax,eax
            mov [esi],al
            mov [edi],al

            mov esi,ESI
            tail
            ret

;   prga :: State s => s -> Char
    prga:
            head
            mov ESI,esi
            pop eax
            mov S,eax

        .init:
            mov edx,S
            mov esi,edx
            add esi,0x100
            mov edi,esi
            inc edi

        .generate:
            xor eax,eax
            mov al,[esi]
            inc al
            mov [esi],al

            mov ah,[edi]
            mov ecx,edx
            xor ebx,ebx
            mov bl,al
            add ecx,ebx
            xor ebx,ebx
            mov bl,[ecx]
            add ah,bl
            mov [edi],ah

        .swap:
            mov ebx,edx
            xor ecx,ecx
            mov cl,ah
            add ebx,ecx
            xor ecx,ecx
            mov cl,[ebx]
            push ecx

            mov ebx,edx
            xor ecx,ecx
            mov cl,al
            add ebx,ecx
            xor ecx,ecx
            mov al,[ebx]

            pop ecx
            mov [ebx],cl
            xor ecx,ecx
            mov cl,ah
            add ecx,edx
            mov [ecx],al
            mov al,[esi]

        .output:
            ; &i = esi
            ; &j = edi
            ; &s = edx
            ; *i = al
            ; *j = ah
            xor ebx,ebx
            mov bl,al
            add ebx,edx
            xor ecx,ecx
            mov cl,[ebx]
            push ecx

            xor ebx,ebx
            mov bl,ah
            add ebx,edx
            xor ecx,ecx
            mov cl,[ebx]

            pop ebx
            add bl,cl
            add ebx,edx
            xor ecx,ecx
            mov cl,[ebx]

        .return:
            mov eax,ecx
            mov esi,ESI
            tail
            ret

    %define cycles 0x1dcd6500
    %undef ESI
    %define ESI [gs8]
    %define ECX [gs1c]

;   whitewash :: State s => s -> ()
    whitewash:
        .init:
            head
            mov ESI,esi
            pop eax
            mov S,eax
            mov ecx,cycles

        .loop:
            ; test ecx,0x00
            cmp ecx,0x00
            je .done

            mov eax,S
            push eax
            mov ECX,ecx
            call prga
            mov ecx,ECX
            dec ecx
            jmp .loop

        .done:
            mov esi,ESI
            tail
            ret

    ; ksawrapper2:
    ;     pushad
    ;     mov gs:0xe0,esp
    ;     sub esp,0x0c
    ;     mov eax,[esp+16]
    ;     push eax
    ;     mov eax,[esp+20]
    ;     push eax
    ;     call ksa
    ;     mov gs:0xd0,eax

    ;     ; mov esp,gs:0xe0
    ;     add esp,0x0c
    ;     popad
    ;     mov eax,gs:0xd0
    ;     ret

    ; piwrapper2:
    ;     pushad
    ;     mov gs:0xe4,esp
    ;     sub esp,0x0c
    ;     mov eax,[esp+16]
    ;     push eax
    ;     call prgainit
    ;     mov gs:0xd4,eax

    ;     mov esp,gs:0xe4
    ;     popad
    ;     mov eax,gs:0xd4
    ;     ret

    ; prgawrapper2:
    ;     pushad
    ;     mov gs:0xe8,esp
    ;     sub esp,0x0c
    ;     mov eax,[esp+16]
    ;     push eax
    ;     call prga
    ;     mov gs:0xd8,eax

    ;     mov esp,gs:0xe8
    ;     popad
    ;     mov eax,0xd8
    ;     ret

    gsvars ; @REM










        















