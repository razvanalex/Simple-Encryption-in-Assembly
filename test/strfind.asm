global strfind

;--------------------------------------------------------------------
; This functions finds a substring into a string. It returns 1 if
; the substring is found and 0 otherwise.
;
; C syntax declaration: int strfind(char *src, char *dest)
;--------------------------------------------------------------------
strfind:	
	push ebp
	mov ebp, esp

	mov ebx, [ebp + 8]			; address of source string
	mov edx, [ebp + 12]			; address of substring
	mov ecx, 0					; set ecx to -1


find_again:
	dec ecx

find_first_letter:
	xor esi, esi
	inc ecx
	mov al, [edx]
	cmp byte [ebx + ecx], 0x0
	je return_0
	cmp [ebx + ecx], al
	jne find_first_letter

check_letters:
	inc ecx
	inc esi
	mov al, [edx + esi]
	cmp [ebx + ecx], al
	je check_letters
	cmp byte [edx + esi], 0x0
	jne find_again

	cmp esi, 0x0
	jne return_1

return_0:
	mov eax, 0x0
	jmp exit_strfind

return_1:
	mov eax, 0x1

exit_strfind:
	leave
	ret