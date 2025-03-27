; hash.asm
%include "util.asmh"
bits 32
global hash
global kdf

section .data4 write exec   ; @REM
    pbkdf1:
        .p          resd 0x01
        .s          resd 0x01
        .c          resb 0x01
        .nullsalt   dd 0x00
        .len        resb 0x01
    dk              resb 0x14
                    db 0x00
    hh:
        .h0         dd 0x01234567
        .h1         dd 0x89abcdef
        .h2         dd 0xfedcba98
        .h3         dd 0x76543210
        .h4         dd 0xf0e1d2c3
    state:
        .salt       resd 0x01
        .msg        resd 0x01
        .w:
        .ml         dd 0x80,0x00
        .padding    resb 0x38
                    resb 0x40
                    resb 0x100
    a               resd 0x01
    b               resd 0x01
    c               resd 0x01
    d               resd 0x01
    e               resd 0x01
    f               resd 0x01
    k               resd 0x01
    ; gs0             resd 0x01
    ; gs4:            resb 0x01
    ;     gs5         resb 0x02
    ;     gs6         resb 0x01
    ; gs8             resd 0x01
    ; gsc             resd 0x01
    ; gs10            resd 0x01
    ; gs14            resd 0x01
    ; gs1c            resd 0x01
    _esi            resd 0x01
    _ecx            resd 0x01
        

;   hash :: Destination -> String -> String -> Int -> Bool
    hash:
            head
            ; mov ebx,gs:0x08
            ; mov [gs8],ebx
            ; mov ebx,gs:0x0c
            ; mov [gsc],ebx
            ; mov ebx,gs:0x10
            ; mov [gs10],ebx
            ; mov ebx,gs:0x14
            ; mov [gs14],ebx

            mov [gs8],esi
            mov [gsc],edi
            
    init:
            pop eax
            mov [gs10],eax

            pop eax
            mov ebx,state.msg
            mov [ebx],eax

            pop eax
            mov ebx,state.salt
            mov [ebx],eax

            pop ecx
            mov [gs14],ecx
            pushgsad

        .zero:
            xor eax,eax
            mov edi,[gs10]
            mov ecx,0x14
            rep stosb
            mov ecx,[gs14]

            mov ebx,state.ml
            add ebx,0x04
            add ecx,0x03
            mov [ebx],ecx

            cmp ecx,0x37
            jle copy.init
            xor eax,eax
            popgsad ebx
            tail
            ret

    copy:
        .init:
            mov ebx,state.msg
            mov eax,[ebx]
            add eax,ecx
            sub eax,0x04
            mov edx,state.padding
            mov ebx,edx
            mov edx,state.salt
            mov esi,[edx]
            add esi,0x02

            ; eax = msg last char
            ; ebx = "padding" first char
            ; ecx = length
            ; esi = salt last char
            mov edx,ebx
            add edx,0x37
            mov edi,ecx
            sub edi,0x03
            push edi
            push edx

        .salt:
            mov edi,0x03

        .saltloop:
            movzx edx,byte [esi]
            mov [ebx],dl
            inc ebx
            dec esi
            dec ecx
            dec edi
            jnz .saltloop

        .loop:
            pop edx
            cmp ebx,edx
            jge .done
            cmp ecx,0x00
            je .cond1
            push edx

        .move:
            xor edx,edx
            mov dl,[eax]
            mov [ebx],dl

            dec eax
            inc ebx
            dec ecx
            jmp .loop

        .cond1:
            pop ecx
            add eax,ecx
            push ecx
            push edx
            jmp .move

        .done:
            pop ecx
            
    expand:
            mov edi,state.w
            mov ecx,0x10
            xor eax,eax

        .loop:
            mov ebx,ecx
            sub ebx,0x03
            imul ebx,0x04
            mov eax,[edi+ebx]

            mov ebx,ecx
            sub ebx,0x08
            imul ebx,0x04
            mov edx,[edi+ebx]
            xor eax,edx

            mov ebx,ecx
            sub ebx,0x0e
            imul ebx,0x04
            mov edx,[edi+ebx]
            xor eax,edx

            mov ebx,ecx
            sub ebx,0x10
            imul ebx,0x04
            mov edx,[edi+ebx]
            xor eax,edx

            mov esi,ecx
            leftrotate eax,1
            mov ecx,esi

            mov ebx,ecx
            imul ebx,0x04
            mov [edi+ebx],eax

            inc ecx
            cmp ecx,80
            je .done
            nop
            jmp .loop

        .done:
            nop

    initchunks:
        .a:
            mov eax,a
            mov ebx,hh.h0
            mov ecx,[ebx]
            mov [eax],ecx

         .b:
            mov eax,b
            mov ebx,hh.h1
            mov ecx,[ebx]
            mov [eax],ecx

         .c:
            mov eax,c
            mov ebx,hh.h2
            mov ecx,[ebx]
            mov [eax],ecx

         .d:
            mov eax,d
            mov ebx,hh.h3
            mov ecx,[ebx]
            mov [eax],ecx

         .e:
            mov eax,e
            mov ebx,hh.h4
            mov ecx,[ebx]
            mov [eax],ecx

    mainloop:
        .init:
            xor ecx,ecx
            jmp .switch

        .stage1:
            mov ebx,b
            mov edx,c
            mov esi,[ebx]
            mov edi,[edx]
            and edi,esi

            not esi
            mov edx,d
            mov ebx,[edx]
            and esi,ebx

            or edi,esi
            mov eax,f
            mov [eax],edi

            mov ebx,k
            mov edx,0x01234567
            mov [ebx],edx
            jmp .break

        .stage2:
            mov eax,b
            mov ebx,c
            mov edx,d
            mov esi,[eax]
            mov edi,[ebx]
            mov eax,[edx]
            xor esi,edi

            xor esi,eax
            mov eax,f
            mov [eax],esi

            mov ebx,k
            mov edx,0xa1ebd96e
            mov [ebx],edx
            jmp .break

        .stage3:
            mov eax,b
            mov ebx,c
            mov edx,[eax]
            mov esi,[ebx]
            and esi,edx

            mov eax,d
            mov ebx,[eax]
            and edx,ebx

            mov eax,c
            mov ebx,d
            mov edi,[eax]
            mov eax,[ebx]
            and edi,eax

            or esi,edx
            or esi,edi
            mov eax,f
            mov [eax],esi

            mov ebx,k
            mov edx,0xdcbc1b8f
            mov [ebx],edx
            jmp .break

        .stage4:
            mov eax,b
            mov ebx,c
            mov edx,d
            mov esi,[eax]
            mov edi,[ebx]
            mov eax,[edx]

            xor esi,edi
            xor esi,eax
            mov eax,f
            mov [eax],esi

            mov ebx,k
            mov edx,0xd6c162ca
            mov [ebx],edx
            jmp .break

        .loop:
        .switch:
            cmp ecx,59
            jg .stage4
            cmp ecx,39
            jg .stage3
            cmp ecx,19
            jg .stage2
            jmp .stage1

        .break:
            mov ebx,a
            mov eax,[ebx]
            mov edi,ecx
            leftrotate eax,0x05
            mov ecx,edi

            mov ebx,f
            mov edx,[ebx]
            add eax,edx

            mov ebx,e
            mov edx,[ebx]
            add eax,edx

            mov ebx,k
            mov edx,[ebx]
            add eax,edx

            mov esi,state.w
            mov ebx,ecx
            imul ebx,0x04
            mov edx,[esi+ebx]
            add eax,edx

            mov ebx,e
            mov edx,d
            mov esi,[edx]

            mov [ebx],esi
            mov ebx,c
            mov esi,[ebx]
            mov [edx],esi

            mov edx,b
            mov esi,[edx]
            pushad
            leftrotate esi,0x1e
            pop edi
            pop esi
            pop ebp
            add esp,0x04
            pop ebx
            pop edx
            pop ecx
            pop edi
            mov [ebx],esi

            mov ebx,a
            mov esi,[ebx]
            mov [edx],esi
            mov [ebx],eax

            inc ecx
            cmp ecx,0x50
            je .done
            jmp .loop

        .done:
            nop

    ap:
            mov eax,hh.h0
            mov ebx,a
            mov edx,[eax]
            mov esi,[ebx]
            add edx,esi
            mov [eax],edx

            mov eax,hh.h1
            mov ebx,b
            mov edx,[eax]
            mov esi,[ebx]
            add edx,esi
            mov [eax],edx

            mov eax,hh.h2
            mov ebx,c
            mov edx,[eax]
            mov esi,[ebx]
            add edx,esi
            mov [eax],edx

            mov eax,hh.h3
            mov ebx,d
            mov edx,[eax]
            mov esi,[ebx]
            add edx,esi
            mov [eax],edx

            mov eax,hh.h4
            mov ebx,e
            mov edx,[eax]
            mov esi,[ebx]
            add edx,esi
            mov [eax],edx

    return:
            mov edi,[gs10]
            mov esi,hh
            mov ecx,0x14
            rep movsb

            mov edi,[gsc]
            mov esi,[gs8]
            mov eax,0x01

            popgsad ebx
            ; mov ebx,[gs8]
            ; mov gs:0x08,ebx
            ; mov ebx,[gsc]
            ; mov gs:0x0c,ebx
            ; mov ebx,[gs10]
            ; mov gs:0x10,ebx
            ; mov ebx,[gs14]
            ; mov gs:0x14,ebx

            tail
            ret

    %define iterations 0x0a
    %define outputlen 0x14
    ; %define ESI gs:0x2a
    ; %define ECX gs:0x1a
    %define ESI [_esi]
    %define ECX [_ecx]

;   kdf :: String -> String -> Int -> String
    kdf:
            head
            mov ESI,esi

            pop eax
            mov ebx,pbkdf1.p
            mov [ebx],eax

            pop eax
            mov ebx,pbkdf1.s
            mov [ebx],eax

            pop eax
            mov ebx,pbkdf1.len
            mov byte [ebx],al

        .init:
            xor ecx,ecx
            mov cl,iterations

        .first:
            mov ebx,pbkdf1.len
            xor eax,eax
            mov byte al,[ebx]
            push eax
            mov ebx,pbkdf1.s
            mov eax,[ebx]
            push eax
            mov ebx,pbkdf1.p
            mov eax,[ebx]
            push eax
            mov eax,dk
            push eax

            mov ECX,ecx
            call hash
            mov ecx,ECX

        .loop:
            dec ecx
            cmp ecx,0x00
            je .end

            mov eax,outputlen
            push eax
            mov ebx,pbkdf1.nullsalt
            mov eax,[ebx]
            push ebx
            mov eax,dk
            push eax
            push eax

            mov ECX,ecx
            call hash
            mov ecx,ECX
            jmp .loop

        .end:
            mov eax,dk
            mov esi,ESI
            tail
            ret

            gsvars ; @REM









