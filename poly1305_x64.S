/*
MIT License

Copyright (c) 2021 Keith-Cancel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

.intel_syntax noprefix

#if defined(__linux__)
    #define SYSTEM_V_ABI 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define SYSTEM_V_ABI 1
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
    #define SYSTEM_V_ABI 1
#elif defined(_WIN32) ||  defined(_WIN64) || defined(__WIN32)
    #define WIN_X64_ABI 1
#endif

// define these as empty macros on SYSTEM V
// that way on a non-windows system there is no errors.
#if defined(SYSTEM_V_ABI)
.macro .seh_proc a
.endm

.macro .seh_endproc
.endm

.macro .seh_endprologue
.endm

.macro .seh_stackalloc a
.endm

.macro .seh_pushreg a
.endm
#endif


#ifdef WIN_X64_ABI
    #define st   rcx
    #define dat  r9
    #define len  r8
    #define ledd r8d
    #define lenb r8b

    #define h1   rsi
    #define h1d  esi
    #define h2   rdi
    #define h2d  edi
#elif defined(SYSTEM_V_ABI)
    #define st   rdi
    #define dat  rsi
    #define len  rcx
    #define ledd ecx
    #define lenb cl

    #define h1   r8
    #define h1d  r8d
    #define h2   r9
    #define h2d  r9d
#endif

// r here means the r in the poly1305 algo not register
#define r0   rax
#define r1   rbx

#define h0   rbp
#define h0d  ebp

#define t0  r10
#define t0d r10d
#define t1  r11
#define t2  r12
#define t3  r13
#define t4  r14
#define t5  r15

    .text
.align 16
clamp0:
    .quad 0x0ffffffc0fffffff
clamp1:
    .quad 0x0ffffffc0ffffffc

    .globl poly1305_x64
    .align 16
    .seh_proc poly1305_x64
poly1305_x64:
    push rbx
    .seh_pushreg rbx
    push rbp
    .seh_pushreg rbp
    #ifdef WIN_X64_ABI
        push rdi
        .seh_pushreg rdi
        push rsi
        .seh_pushreg rsi
    #endif
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub  rsp, 24
    .seh_stackalloc	24
    .seh_endprologue
    pxor   xmm0,  xmm0
    movdqa [rsp], xmm0

    mov  r0,  [st + 16]
    mov  r1,  [st + 24]
    and  r0,  [rip + clamp0]
    and  r1,  [rip + clamp1]

    xor  h0d, h0d
    xor  h1d, h1d
    xor  h2d, h2d

    #ifdef WIN_X64_ABI
        mov  dat, rdx
    #else
        mov  len, rdx
    #endif

    # Poly1305 is quite simple although doing the following for
    # foreach 16 byte chunk of c
    #  h  = (h + pad_msb_with_1(c)) * r
    #  h  = h mod (2^130 - 5)
    #  then once done with the repeated applications of the above
    #  h += s
bloop:
    cmp  len, 15
    jbe  trailing

    add  h0, [dat]
    adc  h1, [dat + 8]
    adc  h2, 1

compute_trail:
    # Perform the following aka school book multiplcation
    #
    # It also possible to ignore the most signigant word
    # of H2*R2 since for Poly1305 this multiplcation will
    # never overflow past 256 bits. This is because H
    # will have at most will have a MSB of 131 bits and
    # the clamp function applied to R limits R to 124 bits.
    #
    #         H2 H1 H0
    # x          R1 R0
    #=================
    #            H0*R0
    #         H1*R0
    #      H2*R0
    #         H0*R1
    #      H1*R1
    # + H2*R1
    #---------------------------
    # 6 multiplies and 8 adds

    # First leg
    mov rdx, r0
    mulx t1, t0,  h0
    mulx t2, t4,  h1
    add  t1, t4
    mulx t3, rdx, h2
    adc  t2, rdx
    adc  t3, 0

    # Second leg
    #   flag c - tracking product sum carry
    #   flag o - tracking leg sum carry
    mov  rdx, r1
    mulx t5,  t4, h0
    adcx t1,  t4      # add least significant word to the product
    mov  h0,  t0      # don't need h0 anymore, free up t0

    mulx t4,  t0, h1
    adox t5,  t0      # add with most significant word of last multiply
    adcx t2,  t5      # add next significant word to the product

    mulx t5,  t0, h2
    adox t4,  t0      # add with most significant word of last multiply
    adcx t3,  t4      # add next significant word to the product
    mov  h2,  t2      # copy t2 to h2
    # the the product is t3 h2 t1 h0

    # perform modular reduction via crandall method
    and   h2, 3

    mov   t0, t2      # copy t3 and t2
    mov   h1, t3

    # now need to take the product and divide by 2^130 (aka shift left t3, t2
    # by 2) then multiply by 5. Nicely, multiplying by 5 is (x << 2) + x so we
    # can take advantage of the shift that would be need to by dividide 2^130
    and   t2, -4      # set the low bits to zero

    shrd  t0, h1, 2   # product / 2^130
    shr   h1, 2

    add   t0, t2      # multiply by 5
    adc   h1, t3

    add   h0, t0
    adc   h1, t1
    adc   h2, 0

    # can be done out side the main loop
    # so just commenting out
    #mov  t0, h0
    #mov  t1, h1
    #mov  t2, h2
    #sub  t0, -5
    #sbb  t1, -1
    #sbb  t2, 3
    #cmovge h0, t0
    #cmovge h1, t1
    #cmovge h2, t2

    add   dat, 16
    sub   len, 16
    jmp bloop
trailing:
    test len, len
    # basically a 15 to 1 byte memcpy to the stack
    # was orginally using a loop that copied a byte
    # at a time this was slightly faster on average
    jz   done
    xor  t0,  t0
    test lenb, 8
    jz   four_bytes
    mov  rdx,  [dat]
    mov  [rsp], rdx
    add  t0d,   8
four_bytes:
    test lenb, 4
    jz   two_bytes
    mov  edx, [dat + t0]
    mov  [rsp + t0], edx
    add  t0d, 4
two_bytes:
    test lenb, 2
    jz   one_byte
    mov  dx, [dat + t0]
    mov  [rsp + t0], dx
    add  t0d, 2
one_byte:
    test lenb, 1
    jz   copied
    mov  dl, [dat + t0]
    mov  [rsp + t0], dl
    add  t0d,  1
copied:
    inc  byte ptr [rsp + t0] # set the padding to one
    mov  len, 16
    add  h0,  [rsp]
    adc  h1,  [rsp + 8]
    adc  h2,  0
    jmp  compute_trail
done:
    # check if after partial reduction in the main
    # loop if it needs one further reduction
    mov  t0, h0
    mov  t1, h1
    mov  t2, h2
    sub  t0, -5
    sbb  t1, -1
    sbb  t2, 3

    cmovge h0, t0
    cmovge h1, t1
    cmovge h2, t2

    # add S to the accumlator for the final tag
    add  h0, [st]
    adc  h1, [st + 8]

    mov [st + 32], h0
    mov [st + 40], h1

    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    #ifdef WIN_X64_ABI
        pop rsi
        pop rdi
    #endif
    pop rbp
    pop rbx
    ret
    .seh_endproc