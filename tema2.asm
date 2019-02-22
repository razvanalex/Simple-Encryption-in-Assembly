;--------------------------------------------------------------------
; Author: Smadu Razvan-Alexandru  325CB
;--------------------------------------------------------------------

extern puts
extern printf

section .data
filename: db "./input.dat",0
inputlen: dd 2263
fmtstr: db "Key: %d",0xa,0

section .text
global main

; Functions and helpers functions

;--------------------------------------------------------------------
; This function computes the length of a string. It takes as a 
; parameter an address to a string and it returns the length of the
; string (number of letters until '\0' character). Registers modified
; are edi and eax that should be saved by the user.
;
; C syntax declaration: int strlen(char *src);
;--------------------------------------------------------------------
strlen:
    push ebp
    mov ebp, esp
    
    mov edi, [ebp + 8]  ; address of string
    xor eax, eax        ; set eax to 0
    repne scasb         ; find '\0' character
    sub edi, [ebp + 8]  ; compute length of the string
    dec edi             ; ignore '\0' character
    
    mov eax, edi        ; return length

    leave
    ret


;--------------------------------------------------------------------
; This function takes two strings as parameters and XORs then byte by
; byte. Both parameters are addresses to strings. The function does
; not return any value. The registers modified are eax, ebx, ecx, edx
; that should be saved by the user. 
;
; C syntax declaration: void xor_strings(char *src, char* dest);
;--------------------------------------------------------------------
xor_strings:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]          ; get the address of the source
    mov ebx, [ebp + 12]         ; get the address of the destination
    xor ecx, ecx                ; set ecx to 0
    
xor_byte_by_byte:
    mov dl, [ebx + ecx]         ; get current letter of destination
    xor [eax + ecx], dl         ; xor the two letters
    inc ecx                     ; go to the next letter index
    cmp byte [ebx + ecx], 0x0   ; check if it's 0x0 ('\0')
    jne xor_byte_by_byte        ; repeat until 0x0 ('\0') is found

    leave
    ret


;--------------------------------------------------------------------
; This function takes as parameter an address to a string, XORs the 
; current character of the string with the previous XORed 'block'. 
; It also returns the length of the string. The registers modified
; are eax, ebx, ecx and edx, and they should be saved by the user.
;
; C sytnax declaration: int rolling_xor(char *src);
;--------------------------------------------------------------------
rolling_xor: 
    push ebp,
    mov ebp, esp
    
    mov eax, [ebp + 8]              ; get the address of the string
    xor ecx, ecx                    ; set ecx to 0
    xor ebx, ebx                    ; set ebx to 0

compute_xor:
    mov dl, [eax + ecx]             ; get the current letter
    xor bl, dl                      ; xor current letter with 'block'
    xor [eax + ecx + 1], bl         ; xor the next letter with 'block'
    inc ecx                         ; go to the next letter
    cmp byte [eax + ecx + 1], 0x0   ; check if it's 0x0 ('\0')
    jne compute_xor                 ; repeat until 0x0 ('\0') is found

    inc ecx                         ; consider the first character
    mov eax, ecx                    ; return the lengh of the string

    leave
    ret


;--------------------------------------------------------------------
; Convert ASCII character to hex number. It takes as parameter an 
; address to a byte encoded in ASCII and converts the character to 
; its hex value (e.g. 'A' => 0xA). It changes only eax register. 
; This function does not return any value.
;
; C syntax declaration: void ASCII_to_binary(char *letter);
;--------------------------------------------------------------------
ASCII_to_binary:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]          ; get the address of a character
    cmp byte [eax], '0'         ; check if it CAN BE a number
    jge check_number            ; check if it IS number
    jmp exit_ASCII_to_binary    ; it cannot be a number

check_number:
    cmp byte [eax], '9'         ; check if it's number
    jle convert_number          ; yes! Do the conversion

check_letter:
    cmp byte [eax], 'A'         ; check if it CAN be UpperCase letter
    jge check_upper             ; check if it IS UpperCase letter
    jmp exit_ASCII_to_binary    ; it cannot be a UpperCase letter

check_upper:
    cmp byte [eax], 'Z'         ; check if it is UpperCase letter
    jle convert_upper           ; yes! Do the conversion

check_lower:
    cmp byte [eax], 'a'         ; check if it CAN be LowerCase letter
    jge convert_lower           ; check if it IS LowerCase letter
    jmp exit_ASCII_to_binary    ; it cannot be a LowerCase letter

convert_number:
    sub byte [eax], '0'         ; convert number to hex
    jmp exit_ASCII_to_binary    ; the job is finished

convert_upper:
    sub byte [eax], 'A'         ; compute index in alphabet
    add byte [eax], 0xa         ; convert UpperCase to hex
    jmp exit_ASCII_to_binary    ; the job is finished

convert_lower:
    cmp byte [eax], 'z'         ; check if it is LowerCase letter
    jg exit_ASCII_to_binary     ; no! The job is finished
    sub byte [eax], 'a'         ; compute index in alphabet
    add byte [eax], 0xa         ; convert LowerCase to hex

exit_ASCII_to_binary:
    leave
    ret


;--------------------------------------------------------------------
; Convert short to byte. It takes as parameter an address to a short
; (e.g. (of short): 0x12 0x34) and it gets the last nibble from both 
; bytes and concatenate them into the resulting byte. The resulting 
; byte is stored at address given as second parameter. The next byte 
; to the resulting byte will be set to 0x0, along with the source. 
; The function does not return any value. It changes eax, ebx and edx
; registers.
;
; Note: This function works as described above only for little-endian.
;       
; C syntax declaration: void short_to_byte(short *src, char *dest);
;--------------------------------------------------------------------
short_to_byte:
    push ebp
    mov ebp, esp

    mov ebx, [ebp + 8]          ; the address of a short value
    mov edx, [ebp + 12]         ; the address of the destination byte
    
    xor eax, eax                ; set eax to 0
    mov ax, [ebx]               ; get the value of short
    shl al, 4                   ; shift second nibble
    add al, ah                  ; concatenate both nibbles
    mov word [ebx], 0x0         ; set source to 0x0
    mov byte [edx + 1], 0x0     ; set next byte to 0x0 
    mov [edx], al               ; put result into destination

    leave
    ret


;--------------------------------------------------------------------
; This functions takes as parameters an substring of size of two and 
; the address of a letter where the result will be places and returns
; the address of the character next to the substring. By side effect,
; the function returns the position of the terminator (0x0) after 
; this operation. The function modifies the registers eax and ebx and 
; should be saved by the user. 
;
; E.g. (of string transformation) Let a string: 'a21'
;      0x61 0x32 0x31 => 0x0a 0x02 0x31 => 0xa2 0x00 0x31 which is the 
;      final result. By side effect will be returned the address of 0x00
;      and the function will return the address of 0x31.
;
; C syntax declaration: char* decode_ASCII(char *substr, char **letter);
;--------------------------------------------------------------------
decode_ASCII:
    push ebp
    mov ebp, esp

    mov eax, [ebp + 8]      ; get the address of a substring
    mov ebx, [ebp + 12]     ; get the address of address of the string

    push eax
    call ASCII_to_binary    ; convert first character into binary
    add esp, 4
    
    inc eax                 ; go to next character
    push eax
    call ASCII_to_binary    ; convert second character into binary
    add esp, 4
 
    dec eax                 ; go back to the previous character
    push eax                ; save eax on stack
    push ebx                ; save ebx on stack

    push dword [ebx]
    push eax
    call short_to_byte      ; convert short to byte
    add esp, 8

    pop ebx                 ; get ebx from stack
    pop eax                 ; get eax from stack
    add eax, 0x2            ; point to next letter from string

    inc dword [ebx]         ; point first 0x0 from string

    leave
    ret


;--------------------------------------------------------------------
; This function takes two strings as parameters and XORs them byte
; by byte after the strings ar converted from ASCII to hex.
; The junk resulted will be set to 0x0. The strings have to have the
; same length. Also, this function modifies the registers eax, ebx, 
; ecx, edx, edi and esi, and should be saved by the user. This 
; function does not return any value.
;
; C syntax declaration: void xor_hex_strings(char *str, char *str2);
;--------------------------------------------------------------------
xor_hex_strings:
    push ebp
    mov ebp, esp

    mov ebx, [ebp + 8]      ; get the address of the first string
    mov edx, [ebp + 12]     ; get the address of the second string
    
    push ebx                ; save the address of the first string
    mov esi, esp            ; store the address string 1 in esi

    push edx                ; save the address of the second string
    mov edi, esp            ; store the address string 2 in edi

convert_from_ASCII:
    push edx                ; save edx
    push edi                ; save edi

    push esi
    push ebx
    call decode_ASCII       ; decode two bytes from string 1
    add esp, 8
    mov ebx, eax            ; get returned value

    pop edi                 ; get edi from stack
    pop edx                 ; get edx from stack

    push ebx                ; save ebx
    push esi                ; save esi
    
    push edi
    push edx
    call decode_ASCII       ; decode two bytes from string 2
    add esp, 8
    mov edx, eax            ; get returned value
    
    pop esi                 ; get esi from stack
    pop ebx                 ; get ebx from stack

compute_binary_xor:
    mov eax, [edi]          ; get the address of letter from string 2
    mov ecx, [esi]          ; get the address of letter from string 1

    mov al, [eax - 1]       ; get the character form the second string
    xor [ecx - 1], al       ; xor that character with the one from string 1
    
    mov al, [ebx]           ; get the current character
    cmp al, 0x0             ; check if it's the final of strings
    jnz convert_from_ASCII  ; repeat until 0x0 ('\0') is found

    add esp, 8              ; clear stack

    leave
    ret


;--------------------------------------------------------------------
; This function converts an ASCII character (letter from A to Z or 
; a number from 2 to 7) to an decoded value from base32. 
; E.g. A -> 0x00 | B -> 0x01 | ... | Z -> 0x19 
;      2 -> 0x1A | 3 -> 0x1B | ... | 7 -> 0x1F
;       = -> 0x00 at the end of the encoded text.
;
; These values are stored in hexadecimal in memory as it is show in
; the previous example. This function modifies eax register and
; should be saved by the user. Also, the function is not meant to 
; return any value, but in eax will be found the address given as
; parameter.
;
; C syntax declaration: void ASCII_to_Value_b32(char *letter);
; or (not Recommended): void* ASCII_to_Value_b32(char *letter);
;--------------------------------------------------------------------
ASCII_to_Value_b32:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]             ; the address of the letter
    
    cmp byte [eax], "="            ; check if it is '='
    je is_equal                    
    cmp byte [eax], "A"            ; check if it can be letter from A
    jge is_letter
    cmp byte [eax], "2"            ; check if it can be number from 2
    jge is_number
    jmp exit_ASCII_to_Value_b32    ; otherwise exit

is_equal:
    sub byte [eax], "="            ; convert to 0x0
    jmp exit_ASCII_to_Value_b32

is_letter:
    cmp byte [eax], "Z"            ; check if it's letter
    jg exit_ASCII_to_Value_b32
    sub byte [eax], "A"            ; convert ASCII letter to value
    jmp exit_ASCII_to_Value_b32

is_number:
    cmp byte [eax], "7"            ; check if it's number 
    jg exit_ASCII_to_Value_b32
    sub byte [eax], "2" - 26       ; convert ASCII number to value
    jmp exit_ASCII_to_Value_b32

exit_ASCII_to_Value_b32:
    leave
    ret


;--------------------------------------------------------------------
; This function decodes a 40-bit group (or 8 bytes) from base32 
; values to ASCII characters. In other words, it 'removes' the first
; three '0' bits from each byte and then it concatenates the results.
; The function takes as parameters the address to a group of 8 bytes
; and the destination where the result should be stored. After
; execution this function will return the value through eax register
; and will represent the address to next 0x0 byte (the new '\0' of
; the decoded string). This function will save edi, edx, ecx and 
; ebx registers and it will modify eax register which is also the
; return value.
;
; C syntax declaration: 
;        char* decode_40bit_group(char *group, char *address);
;--------------------------------------------------------------------
decode_40bit_group:
    push ebp
    mov ebp, esp
    
    push edi                    ; save edi on stack
    push edx                    ; save edx on stack
    push ecx                    ; save ecx on stack
    push ebx                    ; save ebx on stack

    mov edi, [ebp + 8]          ; address of group
    mov edx, [ebp + 12]         ; address of location
    mov cl, 0x3                 ; set cl to 0x3
    
    mov ebx, [edi]              ; get value in ebx
    mov [edx], ebx              ; put value at address
    rol byte [edx], cl          ; rotate 1st byte by 0x3
    add cl, 0x3                 ; set cl to 0x6

    mov ebx, [edi + 1]          ; get value in ebx
    mov [edx + 1], ebx          ; put value at address
    rol byte [edx + 1], cl      ; rotate 2nd byte by 0x6
    mov ch, [edx + 1]           ; save byte in ch
    and ch, 0x7                 ; apply mask 00000111 to ch
    or byte [edx], ch           ; add ch to 1st byte
    and byte [edx + 1], 0xC0    ; apply mask 11000000 to 2nd byte
    add cl, 0x3                 ; set cl to 0x9

    mov ebx, [edi + 2]          ; get value in ebx
    mov [edx + 2], ebx          ; put value at address
    rol byte [edx + 2], cl      ; rotate 3rt byte by 0x9
    mov ch, [edx + 2]           ; save byte in ch
    or [edx + 1], ch            ; add ch to 2nd byte
    xor [edx + 2], ch           ; set 3rd byte to 0x0
    add cl, 0x3                 ; go to 4th byte

    mov ebx, [edi + 3]          ; get value in ebx
    mov [edx + 3], ebx          ; put value at address
    rol byte [edx + 3], cl      ; rotate 4th byte by 0xC
    mov ch, [edx + 3]           ; save byte in ch
    mov [edx + 2], ch           ; put ch in 3rd byte
    and byte [edx + 2], 0xF0    ; apply mask 11110000 to 3rd byte
    and ch, 0x1                 ; apply mask 00000001 to ch
    or [edx + 1], ch            ; put the last bit in 2nd byte
    mov byte [edx + 3], 0x0     ; set 4th byte to 0x0
    add cl, 0x3                 ; set cl to 0xE

    mov ebx, [edi + 4]          ; get value in ebx
    mov [edx + 4], ebx          ; put value at address
    rol byte [edx + 4], cl      ; rotate 5th byte by 0xE
    mov ch, [edx + 4]           ; save byte in ch
    mov [edx + 3], ch           ; put ch in 4nd byte
    and byte [edx + 3], 0x80    ; apply mask 10000000 to 4th byte
    and ch, 0xF                 ; apply mask 0000FFFF to ch
    or [edx + 2], ch            ; put last 4 bits in 3rd byte
    mov byte [edx + 4], 0x0     ; set 5th byte to 0x0
    add cl, 0x3                 ; set cl to 0x12

    mov ebx, [edi + 5]          ; get value in ebx
    mov [edx + 5], ebx          ; put value at address
    rol byte [edx + 5], cl      ; rotate 6th byte by 0x12
    mov ch, [edx + 5]           ; save byte in ch
    or [edx + 3], ch            ; put byte in 4th byte
    mov byte [edx + 5], 0x0     ; set 6th byte to 0x0
    add cl, 0x3                 ; set cl to 0x15
    
    mov ebx, [edi + 6]          ; get value in ebx
    mov [edx + 6], ebx          ; put value at address
    rol byte [edx + 6], cl      ; rotate 7th byte by 0x15
    mov ch, [edx + 6]           ; save byte in ch
    mov [edx + 4], ch           ; put ch in 5th byte
    and byte [edx + 4], 0xFC    ; apply mask 11111100 to 5th byte
    and ch, 0x3                 ; apply mask 00000011 to ch
    or [edx + 3], ch            ; add last two bits to 4th byte
    mov byte [edx + 6], 0x0     ; set 7th byte to 0x0
    
    mov ebx, [edi + 7]          ; get value in ebx
    mov [edx + 7], ebx          ; put value at address
    mov ch, [edx + 7]           ; save byte in ch
    or [edx + 4], ch            ; put ch to 5th byte
    mov byte [edx + 7], 0x0     ; set last byte to 0x0

    mov eax, edx                ; copy start of the group to eax 
    add eax, 0x5                ; eax now points to first 0x0 byte

    pop ebx                     ; retrieve ebx from stack
    pop ecx                     ; retrieve ecx from stack
    pop edx                     ; retrieve edx from stack
    pop edi                     ; retrieve edi from stack

    leave
    ret


;--------------------------------------------------------------------
; This function decodes a base32 encoded string. It takes as
; parameter the address of a string and decodes the string. This
; function does not return any value. It modifies eax, ebx, ecx, edx
; registers and should be saved by the user.
;
; C syntax declaration: void base32decode(char *str)
;--------------------------------------------------------------------
base32decode:
    push ebp
    mov ebp, esp

    mov edx, [ebp + 8]          ; address of string
    mov ebx, edx                ; set ebx to 0

convert_ASCII:
    mov eax, edx                ; save address from edx to eax
    xor ecx, ecx                ; set ecx to 0x0

convert_40bits:
    push eax
    call ASCII_to_Value_b32     ; convert ASCII to hexa base32 value
    add esp, 4
    
    inc eax                     ; go to next letter
    inc ecx                     ; go to next index letter
    cmp ecx, 0x8                ; check if there is an 8-byte group converted
    jl convert_40bits           ; do until ecx is 0x8
    
    push ebx
    push edx
    call decode_40bit_group     ; decode the 8-byte group
    add esp, 8

    mov ebx, eax                ; get the new address returned in ebx

    add edx, 0x8                ; go to next 8-byte group
    cmp byte [edx], 0x0         ; check if next letter is '\0'
    jne convert_ASCII           ; repeat until '\0' is found

    leave
    ret


;--------------------------------------------------------------------
; This functions finds a substring into a string. It returns 1 if
; the substring is found and 0 otherwise. It saves ebx, ecx, edx
; and esi registers. The function takes as parameters the address of
; source string and the address of 'to find' string.
;
; C syntax declaration: int strfind(char *src, char *dest)
;--------------------------------------------------------------------
strfind:    
    push ebp
    mov ebp, esp
    
    push ebx                    ; save ebx to stack
    push ecx                    ; save ecx to stack
    push edx                    ; save edx to stack
    push esi                    ; save esi to stack

    mov ebx, [ebp + 8]          ; address of source string
    mov edx, [ebp + 12]         ; address of substring
    mov ecx, 0x0                ; set ecx to -1

find_again:
    dec ecx                     ; decrement ecx to not miss any letter

find_first_letter:
    xor esi, esi                ; set esi to 0x0
    inc ecx                     ; go to next letter
    mov al, [edx]               ; store [edx] letter to al
    cmp byte [ebx + ecx], 0x0   ; compare current letter to 0x0
    je return_0                 ; return 0 (the substring is not found)
    cmp [ebx + ecx], al         ; check if it's found first common letter
    jne find_first_letter       ; continue finding first letter

check_letters:
    inc ecx                     ; go to next letter from src string
    inc esi                     ; go to next letter from dst string
    mov al, [edx + esi]         ; store letter from dst to al
    cmp [ebx + ecx], al         ; compare both letters
    je check_letters            ; continue comparing
    cmp byte [edx + esi], 0x0   ; if 0x0 is found then it's ok
    jne find_again              ; if not, continue finding

    cmp esi, 0x0                ; check if the string was found
    jne return_1                ; if yes, return 1

return_0:
    pop esi                     ; get esi from stack
    pop edx                     ; get edx from stack
    pop ecx                     ; get ecx from stack
    pop ebx                     ; get ebx from stack
    mov eax, 0x0                ; set return value to 0
    jmp exit_strfind            ; exit function

return_1:
    pop esi                     ; get esi from stack
    pop edx                     ; get edx from stack
    pop ecx                     ; get ecx from stack
    pop ebx                     ; get ebx from stack
    mov eax, 0x1                ; set return value to 1

exit_strfind:
    leave
    ret


;--------------------------------------------------------------------
; This function applies brute force over a string, taking each 
; character from ASCII (from 0x00 to 0xff) and then checking each
; answer if the word "force" is found. If yes, stop finding and 
; return by side effect the key. This function does not return
; an value. This function modifies ebx, ecx, edx, esi, edi and 
; should be saved by the user.
;
; C syntax declaration: 
;   void bruteforce_singlebyte_xor(char *addr_str, char *key_addr)
;--------------------------------------------------------------------
bruteforce_singlebyte_xor:
    push ebp
    mov ebp, esp
         
    mov edi, [ebp + 8]              ; get the address of the source
    mov ebx, [ebp + 12]             ; get the address of the key
    mov edx, 0x1                    ; set edx to 0x1
    
    sub esp, 0x6                    ; reserve space for "force" string
    mov dword [ebp - 6], 0x63726f66 ; put "forc" on stack 
    mov word [ebp - 2], 0x0065      ; put "e\0" on stack    
    lea esi, [ebp - 6]              ; address of "force" string
    
    push ebx                        ; save ebx to stack

check_each_key:
    xor ecx, ecx                    ; set ecx to 0x0
    
xor_byte_with_char:
    xor byte [edi + ecx], dl        ; xor encoded letter with possible key 
    inc ecx                         ; go to the next letter index
    cmp byte [edi + ecx], 0x0       ; check if it's 0x0 ('\0')
    jne xor_byte_with_char          ; repeat until 0x0 ('\0') is found
    
    push esi
    push edi
    call strfind                    ; find "force" in decoded string
    add esp, 8    

    cmp eax, 0x1                    ; check if the answer is yes
    je exit_bruteforce              ; if yes, exit

    xor ecx, ecx                    ; set ecx to 0x0

revert_xor:
    xor byte [edi + ecx], dl        ; revert letter
    inc ecx                         ; go to the next letter index
    cmp byte [edi + ecx], 0x0       ; check if it's 0x0 ('\0')
    jne revert_xor                  ; repeat until 0x0 ('\0') is found

    inc dl                          ; go to next possible key
    mov dh, 0xff                    ; store last possible key value
    cmp dh, dl                      ; check if there are remained keys
    jne check_each_key              ; check other key
    
exit_bruteforce:
    pop ebx                         ; get ebx from stack
    mov dword [ebx], 0x0            ; set [ebx] to 0
    mov [ebx], dl                   ; add to [ebx], the key

    leave
    ret


;--------------------------------------------------------------------
; This function subtitues a letter given as parameter (it's address)
; and is substituded according to the substitution table which is 
; also given as parameter. This function save ecx, ebx, edi and eax
; and does not return any value (or is not meant to do that).
;
; C syntax declaration: 
;   void substitute_letter(char *addr_char, char *substitution_table)
;--------------------------------------------------------------------
substitute_letter:
    push ebp
    mov ebp, esp

    push ecx                        ; save ecx on stack
    push ebx                        ; save ebx on stack
    push edi                        ; save edi on stack
    push eax                        ; save eax on stack

    mov edi, [ebp + 8]              ; get the address of the letter
    mov ebx, [ebp + 12]             ; get the address of the table
    mov ecx, -1                     ; set ecx to -1

find_crt_letter:
    add ecx, 0x2                    ; go to next letter
    cmp byte [ebx, ecx], 0x0        ; check for 0x0
    je exit_substitute_letter       ; if yes, exit wihtout substution
    mov al, [ebx + ecx]             ; put letter on eax
    cmp byte [edi], al              ; compare letters
    jne find_crt_letter             ; continue finding letter
    
    dec ecx                         ; set index of new letter
    mov al, [ebx + ecx]             ; move new letter in eax
    mov [edi], al                   ; substitute letter from source

exit_substitute_letter:
    pop eax                         ; get eax from stack
    pop edi                         ; get edi from stack
    pop ebx                         ; get ebx from stack
    pop ecx                         ; get ecx from stack

    leave
    ret


;--------------------------------------------------------------------
; This function brakes any encrypted text using a substitution tabel
; given also as parameter. This function does not return any value 
; and modifies edi, ebx, eax and ecx registers and should be saved
; by user.
;
; C syntax declaration: 
;   void break_substitution(char *addr_str, char *substitution_table)
;--------------------------------------------------------------------
break_substitution:
    push ebp
    mov ebp, esp
    
    mov edi, [ebp + 8]              ; get the address of the string
    mov ebx, [ebp + 12]             ; get the address of the table
    xor ecx, ecx                    ; set ecx to 0x0
    
    ; Set the precomputed substitution table which is:
    ; aqbxc dpedflgohmiijvktlsmunwojpkqarbsrtgufvzwcx.yhzy e.n
    mov dword [ebx +  0], "aqbr"    ; put "aqbr" on stack
    mov dword [ebx +  4], "cwde"    ; put "cwde" on stack
    mov dword [ebx +  8], "e fu"    ; put "e fu" on stack
    mov dword [ebx + 12], "gthy"    ; put "gthy" on stack
    mov dword [ebx + 16], "iijo"    ; put "iijo" on stack
    mov dword [ebx + 20], "kplf"    ; put "kplf" on stack
    mov dword [ebx + 24], "mhn."    ; put "mhn." on stack
    mov dword [ebx + 28], "ogpd"    ; put "ogpd" on stack
    mov dword [ebx + 32], "qars"    ; put "qars" on stack
    mov dword [ebx + 36], "sltk"    ; put "sltk" on stack
    mov dword [ebx + 40], "umvj"    ; put "umvj" on stack
    mov dword [ebx + 44], "wnxb"    ; put "wnxb" on stack
    mov dword [ebx + 48], "yzzv"    ; put "yzzv" on stack
    mov dword [ebx + 52], " c.x"    ; put " c.x" on stack
    mov dword [ebx + 56], 0x0       ; put 0x0 on stack

substitute_each_letter:
    lea eax, [edi + ecx]            ; get address of letter

    push ebx
    push eax
    call substitute_letter          ; substitute letter
    add esp, 8

    inc ecx                         ; go to next letter
    cmp byte [edi + ecx], 0x0       ; check for 0x0 character
    jne substitute_each_letter      ; continue until 0x0 is found

    leave
    ret


;--------------------------------------------------------------------
; Main function. This is the entry point of the program.
;--------------------------------------------------------------------
main:
    push ebp
    mov ebp, esp
    sub esp, 2300
    
    ; fd = open("./input.dat", O_RDONLY);
    mov eax, 5
    mov ebx, filename
    xor ecx, ecx
    xor edx, edx
    int 0x80
    
    ; read(fd, ebp-2300, inputlen);
    mov ebx, eax
    mov eax, 3
    lea ecx, [ebp-2300]
    mov edx, [inputlen]
    int 0x80

    ; close(fd);
    mov eax, 6
    int 0x80

    ; all input.dat contents are now in ecx (address on stack)
    sub esp, 4                  ; alloc memory for address of string
    mov [ebp - 2304], ecx       ; store ecx value on stack
    
    ; TASK 1: Simple XOR between two byte streams
    ; Compute addresses on stack for str1 and str2
    push dword [ebp - 2304]
    call strlen                 ; compute length of 1st string (or 2nd)
    add esp, 4

    mov ecx, [ebp - 2304]       ; get address from stack for speed
    mov ebx, ecx                ; store address of first string
    mov edx, ecx                ; prepare computing address of 2nd string
    inc eax                     ; consider '\0' to length
    add edx, eax                ; compute address of 2nd string
    push eax                    ; save index for next exercise

    ; XOR them byte by byte
    push edx
    push ebx
    call xor_strings
    add esp, 8

    ; Print the first resulting string
    push dword [ebp - 2304]
    call puts
    add esp, 4

    ; TASK 2: Rolling XOR
    ; Compute address on stack for str3
    pop eax                     ; get index for next exercise 
    shl eax, 1                  ; compute index for for str3
    add [ebp - 2304], eax       ; compute address for str3

    ; Apply rolling_xor on string
    push dword [ebp - 2304]
    call rolling_xor
    add esp, 4

    inc eax                     ; consider 0x0 to length
    push eax                    ; save index of the next string

    ; Print the second resulting string
    push dword [ebp - 2304]
    call puts
    add esp, 4

    ; TASK 3: XORing strings represented as hex strings
    ; Compute addresses on stack for strings 4 and 5
    pop eax                     ; get index of the string 4
    add [ebp - 2304], eax       ; compute address of string 4

    push dword [ebp - 2304]
    call strlen                 ; get strlen of string 4
    add esp, 4

    mov ebx, [ebp - 2304]       ; copy addres of strings 4 in ebx
    mov edx, [ebp - 2304]       ; copy addres of strings 5 in edx
    inc eax                     ; add '\0' to length
    add edx, eax                ; compute address for string 5 in edx

    shl eax, 1                  ; multiply by 2
    add eax, [ebp - 2304]       ; compute address of string for next task
    push eax                    ; store computed address
    
    ; Apply xor_hex_strings
    push edx
    push ebx
    call xor_hex_strings
    add esp, 8

    ; Print the third string
    push dword [ebp - 2304]
    call puts
    add esp, 4
    
    ; TASK 4: decoding a base32-encoded string
    ; Compute address on stack for string 6
    pop eax                     ; get address of string 6 from stack
    mov [ebp - 2304], eax       ; put that address in our variable
    mov ecx, eax                ; put the address in ecx for strlen

    push ecx
    call strlen                 ; compute the length of thhe string
    add esp, 4
    push eax                    ; save the length on stack

    ; Apply base32decode
    push dword [ebp - 2304]
    call base32decode
    add esp, 4

    ; Print the fourth string
    push dword [ebp - 2304]
    call puts
    add esp, 4

    ; TASK 5: Find the single-byte key used in a XOR encoding
    ; Determine address on stack for string 7
    pop eax                     ; get the length from stack of the string 6
    inc eax                     ; consider 0x0 at the final
    add [ebp - 2304], eax       ; compute the address of string 7
    sub esp, 4                  ; alloc memory for key
    lea ebx, [ebp - 2308]       ; get address of the new variable created

    ; Apply bruteforce_singlebyte_xor
    push ebx                    
    push dword [ebp - 2304]
    call bruteforce_singlebyte_xor
    add esp, 8

    ; Print the fifth string and the found key value
    push dword [ebp - 2304]
    call puts
    add esp, 4

    push dword [ebp - 2308]
    push fmtstr
    call printf
    add esp, 8

    ; TASK 6: Break substitution cipher
    ; Determine address on stack for string 8
    push dword [ebp - 2304]
    call strlen                 ; get length of string 7
    add esp, 4

    inc eax                     ; consider 0x0 at the final of string
    add dword [ebp - 2304], eax ; compute address of string 8

    ; Substitution table: 
    sub esp, 60                 ; alloc space for substitution table   
    lea eax, [ebp - 2368]       ; get address of substitution table
    sub esp, 4                  ; alloc memory for address
    mov dword [ebp - 2372], eax ; put the address on stack

    ; Break_substitution    
    push dword [ebp - 2372]
    push dword [ebp - 2304]
    call break_substitution
    add esp, 8

    ; Print final solution (after some trial and error)
    push dword [ebp - 2304]
    call puts
    add esp, 4

    ; Print substitution table
    push dword [ebp - 2372]
    call puts
    add esp, 4

    ; Phew, finally done
    xor eax, eax
    leave
    ret
