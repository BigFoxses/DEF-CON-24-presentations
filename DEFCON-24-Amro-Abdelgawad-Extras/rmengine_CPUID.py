# Amro Abdelgawad
# The Remote Metamorphic Eninge - Sample1_cpuid

import struct
import commands
import sys
import random
import socket
from timeit import default_timer as timer

from capstone import *


asm = ""
name = 'sample1_cpuid'
APIhashes = ""
morphe = 1



def _hex(code):
    return "".join("{:02x}".format(ord(c)) for c in code)

def rol( x, n):
    return  (x << n) | (x >> (32-n))
def ror( x, n):
    return  (x >> n) | (x << (32-n))

def _ror(response, operand):
    return ((response >> (32 - operand)&0xffffffff) | ((response << operand)&0xffffffff))&0xffffffff
def _not(response, operand):
    return (~response&0xffffffff)
def _add(response, operand):
    return ((response&0xffffffff) - (operand&0xffffffff))&0xffffffff
def _sub(response, operand):
    return ((response&0xffffffff) + (operand&0xffffffff))&0xffffffff
def _xor(response, operand):
    return ((response&0xffffffff) ^ (operand&0xffffffff))&0xffffffff
def DecryptResponse(response, key):
    response = response&0xffffffff
    key = key[:-1]
    key.reverse()
    #print key
    for i in range(len(key)):
        response = reverse_ins[int(key[i][0])](response, key[i][1])
    return response

reverse_ins = {0 : _ror,
    1 : _not,
    2 : _add,
    3 : _sub,
    4 : _xor,
}

def gen_block_mutation_key():
    
    key = []
    
    r = 0
    code_len = 0
    
    for i in range(10):
        r = random.randrange(10)
        
        if r == 0:  #ROR
            key.append([r,random.randrange(30)+1])
            code_len += 3;
        
        if r == 1: #NOT
            # eliminating adjacent "NOT" operation selection.
            if len(key) > 2 and key[len(key)-2] == 1:
                # replace it with an XOR
                r = 2
            else:
                key.append([r,-1])
                code_len += 2
        
        if r == 2: #ADD
            key.append([r,random.getrandbits(32)])
            code_len += 5
        
        if r == 3: #SUB
            key.append([r,random.getrandbits(32)])
            code_len += 5
        
        if r == 4: #XOR
            key.append([r,random.getrandbits(32)])
            code_len += 5

    if code_len == 0:
        key.append([2,random.getrandbits(32)])
        code_len += 5

    key.append(code_len)
    
    return key


def gen_instruction(op):
    ins = ""
    
    if op[0] == 0:      #ror
        ins += "    mov reg4_4, 0x11223344\n"
        ins += "    ror reg4_4, %d\n"%op[1]
        ins += "    mov [reg1_4], reg4_4\n"
        ins += "    add reg1_4, 4\n"
        if op[1] == 1:
            ins_length = 12
        else:
            ins_length = 13
    elif op[0] == 1:    #not
        ins += "    mov reg4_4, 0x11223344\n"
        ins += "    not reg4_4\n"
        ins += "    mov [reg1_4], reg4_4\n"
        ins += "    add reg1_4, 4\n"
        ins_length = 12
    elif op[0] == 2:    #add
        ins += "    add dword [reg1_4], 0x11223344\n"
        ins += "    add reg1_4, 4\n"
        ins_length = 9
    elif op[0] == 3:    #sub
        ins += "    sub dword [reg1_4], 0x11223344\n"
        ins += "    add reg1_4, 4\n"
        ins_length = 9
    elif op[0] == 4:    #xor
        ins += "    xor dword [reg1_4], 0x11223344\n"
        ins += "    add reg1_4, 4\n"
        ins_length = 9

    return [ins,ins_length]


def reassemble(code):

    block_count = 0
    reassembled_code = ""
    blocks = code.split("\x60\x9c\xE8")
    for block in blocks[1:]:
        print _hex(block)
        try:
            num_operands = ord(block[4])
            if num_operands > 10:
                continue
            index = 5 # mutation key index
            
            decoder = block.split("\x9d\x61")[0][5+(num_operands*5):]
            original_code = "\x9d\x61"+block.split("\x9d\x61")[1][:len(decoder)-2]
            
            num_dwords = 5
            selfmod_ops = 0
            i = 0 # pointer to original code
            while selfmod_ops < num_dwords:
                index = 5
                for op in range(num_operands):
                    opcode                 = ord(block[index])
                    operand                = struct.unpack('<L',block[index+1:index+5])[0]
                    original_code_bytes    = struct.unpack('<L',original_code[i:i+4])[0]
                    original_decoder_bytes = struct.unpack('<L',decoder[i:i+4])[0]

                    if opcode == 0: #reverse ror: rol
                        mbytes = rol( original_code_bytes, operand)
                        mbytes = struct.pack('<L',mbytes&0xffffffff)
                    elif opcode == 1: # reverse not: not
                        mbytes = ~original_code_bytes
                        mbytes = struct.pack('<L',mbytes&0xffffffff)
                    elif opcode == 2: # reverse add: sub
                        mbytes = original_code_bytes - original_decoder_bytes
                        mbytes = struct.pack('<L',mbytes&0xffffffff)
                    elif opcode == 3: # reverse sub: add
                        mbytes = original_decoder_bytes - original_code_bytes
                        mbytes = struct.pack('<L',mbytes&0xffffffff)
                    elif opcode == 4: # reverse xor: xor
                        mbytes = original_code_bytes ^ original_decoder_bytes
                        mbytes = struct.pack('<L',mbytes&0xffffffff)
                    
                    decoder = decoder.replace('\x44\x33\x22\x11', mbytes, 1)
                    
                    i += 4
                    index += 5
                    selfmod_ops += 1
                    if selfmod_ops == num_dwords:
                        break
        
            block = block.replace(original_code, decoder)
        except:
            pass
        
        for i in range(num_operands):
            random_operand = "".join( chr(random.randint(0, 255)) for i in range(4))
            block = block.replace('\x44\x33\x22\x11',random_operand,1)

        reassembled_code += ("\x60\x9c\xE8"+block)
        block_count+=1
    
    return reassembled_code


def api_hash(name):
    func_hash = int(0)
    for char in name:
        func_hash = ror(func_hash,0x11)
        func_hash &= 0xFFFFFFFF
        func_hash += ord(char)
        func_hash &= 0xFFFFFFFF
    return func_hash


def module_hash(name):
    func_hash = int(0)
    for char in name:
        char = chr(ord(char)|0x20)
        func_hash = ror(func_hash,0x11)
        func_hash &= 0xFFFFFFFF
        func_hash += ord(char)
        func_hash &= 0xFFFFFFFF
    return func_hash


def genkey():
    
    key = []
    key.append([2,random.getrandbits(32)])
    
    r = 0
    code_len = 5
    
    for i in range(50):
        r = random.randrange(10)
        
        if r == 0:  #ROR
            key.append([r,random.randrange(30)+1])
            code_len += 3;
        
        if r == 1: #NOT
            # eliminating adjacent "NOT" operation selection.
            if len(key) > 2 and key[len(key)-2] == 1:
                # replace it with an XOR
                r = 2
            else:
                key.append([r,-1])
                code_len += 2
        
        if r == 2: #ADD
            key.append([r,random.getrandbits(32)])
            code_len += 5
        
        if r == 3: #SUB
            key.append([r,random.getrandbits(32)])
            code_len += 5
        
        if r == 4: #XOR
            key.append([r,random.getrandbits(32)])
            code_len += 5
    
    key.append(code_len)
    
    return key

def gen_mutation_code(key):
    
    code = ""
    
    for i in range(len(key)-1):
        if (key[i][0] == 0): #ror
            code += "\xc1"
            code += "\xC8"
            code += struct.pack('B', key[i][1]) #operand
            continue
        
        if (key[i][0] == 1): #not
            code += "\xF7"
            code += "\xD0"
            continue
        
        if (key[i][0] == 2): #add
            code += "\x05"
        elif (key[i][0] == 3): #sub
            code += "\x2D"
        elif (key[i][0] == 4): #xor
            code += "\x35"
        code += struct.pack('<L',key[i][1]&0xffffffff)
    
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    
    mutation_code = ""
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, 0x1000):
        mutation_code += "    %s %s\n"%(mnemonic, op_str)

    return mutation_code


def regswap(asm, type=0):
    if type == 0:
        registers = ['ebx','edx','ecx','edi']
    else:
        registers = ['eax','ebx','edx','ecx']
    random.shuffle(registers)
    asm = asm.replace('reg1_4', registers[0])
    asm = asm.replace('reg1_2', registers[0][1:])
    asm = asm.replace('reg1_1', registers[0][1:-1]+'l')
    asm = asm.replace('reg2_4', registers[1])
    asm = asm.replace('reg2_2', registers[1][1:])
    asm = asm.replace('reg2_1', registers[1][1:-1]+'l')
    asm = asm.replace('reg3_4', registers[2])
    asm = asm.replace('reg3_2', registers[2][1:])
    asm = asm.replace('reg3_1', registers[2][1:-1]+'l')
    asm = asm.replace('reg4_4', registers[3])
    asm = asm.replace('reg4_2', registers[3][1:])
    asm = asm.replace('reg4_1', registers[3][1:-1]+'l')
    
    return asm

def string(str_name,str_value):
    global asm
    
    block = """get_%s:
    call got_%s
%s:
    db "%s", 0x00
$strings$
    """%(str_name,str_name,str_name,str_value)
    asm = asm.replace('$strings$',block,1)

def call(func,*args):
    global asm
    block = ""
    for arg in args:
        if type(arg) is IntType:
            pass

def gencode(asm):
    global morphe
    
    
    asm = regswap(asm)

    asm = asm.lower()

    key = genkey()
    mutation_code = gen_mutation_code(key)
    head = gen_mutation_code(genkey())
    asm  = asm.replace("$head$",head,1)
    asm  = asm.replace("$mutation$",mutation_code,1)
    asm  = asm.replace("$deadcode$","    nop\n"*random.randrange(100,300))


    input = ""

    if morphe:
        skip_asm = ""
        block_head = "    pushad\n    pushf\n"

        line_count = 0
        blocks = []
        asm = asm.lower()
        asm = regswap(asm)
        
        for line in asm.split('\n'):
            block = ""
            if not len(line) or line[0] == ';' or line[0] == '[' or 'bits 32' in line or 'global' in line:
                skip_asm += line+'\n'
                continue
            if 'end:' in line:
                block += "line%d:\n"%line_count
                block += line+'\n'
                blocks.append(block)
                break
            
            block_mutation_key = gen_block_mutation_key()
            block = "line%d:\n"%line_count
            if ":" in line: block += line+'\n'
            block += block_head
            block += "    call line%d_1\n"%line_count
            block += "    db %d\n"%(len(block_mutation_key)-1)
            for opcode, operand in block_mutation_key[:-1]:
                block += "    db %d\n    dd %d\n"%(opcode,operand)
        
            
            selfmod_ops = 0
            # Decrypt 20 bytes "5*4"
            num_dwords = 5
            gen_block = ""
            gen_block_length = 0
            while selfmod_ops < num_dwords:
                for op in block_mutation_key[:-1]:
                    gen_ins = gen_instruction(op)
                    gen_block += gen_ins[0]
                    gen_block_length += gen_ins[1]
                    selfmod_ops += 1
                    if selfmod_ops == num_dwords:
                        break
        
            p = 3
        
            gen_block_length += 10
            block += "    nop\n"
            block += "    mov reg3_4, %d\n"%(((len(block_mutation_key)-1)*5)+gen_block_length+p)
            block += "    add reg1_4, reg3_4\n"
            block += "    mov reg3_4, reg1_4\n"
            block += gen_block
            block += "    jmp reg3_4\n"
            
            
            block += "line%d_2:\n"%line_count
            block += "    popf\n    popad\n"

            if ':' not in line:
                block += line+'\n'
            block += "    jmp long line%d\n"%(line_count+1)
            block += "    nop\n"*(gen_block_length)
            block += "line%d_1:\n"%line_count
            block += "    mov reg1_4, [esp]\n"
            block += "    nop\n"*random.randrange(3)
            block += "    mov reg2_1, 0xe9\n"
            block += "    test reg2_4, reg2_4\n"*random.randrange(2)
            block += "    mov byte [reg1_4], reg2_1\n"
            block += "    xor reg4_4, 0\n"*random.randrange(2)
            block += "    mov reg2_4, 0x%08x\n"%(((len(block_mutation_key)-1)*5)-5+gen_block_length+p)
            block += "    mov dword [reg1_4+1], reg2_4\n"
            block += "    ret\n"
            
            block = regswap(block,2)
            
            if line_count == 0:
                firstblock = block
            else:
                blocks.append(block)
            line_count += 1
            
        blocks.append(APIhashes)
        random.shuffle(blocks)
        
        asm = "[SECTION .text]\nBITS 32\nglobal _start\n"+firstblock
        for block in blocks:
            asm += block
        

    return [asm,key]


HOST = '127.0.0.1'
PORT = 11232

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'Socket created'

try:
    server_socket.bind((HOST, PORT))
except socket.error, msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

print 'Socket bind complete'

server_socket.listen(10)
print 'TCP Server Waiting for connections on port %d'%PORT

client, addr = server_socket.accept()
print 'Connected with ' + addr[0] + ':' + str(addr[1])


cpuid_asm = """;machinecode: ''
[SECTION .text]
BITS 32
global _start
_start:
    $head$
    $deadcode$
    push reg1_4
    push reg2_4
    push reg3_4
    push reg4_4
    xor eax, eax	; CPUID COMMAND = 0
    $deadcode$
    cpuid           ; Executing the cpuid command
    mov eax, ebx	; returning ebx value
    pop reg4_4
    pop reg3_4
    pop reg2_4
    pop reg1_4
    $mutation$
    ret
    $deadcode$
end:
"""

while 1:
    
    asm,key = gencode(cpuid_asm)

    f = open(name+".s",'w+')
    f.write(asm)
    f.close()
    print "[+] challenge assembly code generated and written to %s.s"%name
    print "[+] assembling %s.s"%name
    retvalue = commands.getstatusoutput("nasm -f bin -o %s.bin %s.s"%(name,name))
    if retvalue[1]:
        print retvalue[1]
        sys.exit(0)
    print "[+] parsing machinecode @%s.bin"%name

    f = open('%s.bin'%name,'r+b')
    code = f.read()
    f.close()


    code = reassemble(code)
    f = open('%s.selfmodifying.bin'%name,'w+b')
    f.write(code)
    f.close()
    
    size = len(code)
    print "[+] challenge binary code size: %d"%size
    client.send(struct.pack('!l',size))
    client.send(code)
    challenge_timer = timer()
    encrypted_response = client.recv(4)
    response_timer = timer()
    response_time = (response_timer-challenge_timer)*1000.0
    encrypted_response = struct.unpack('!l',encrypted_response)[0]
    decrypted_response = DecryptResponse(encrypted_response, key)
    print "[+] encrypted response: 0x%08x = %d"%(encrypted_response&0xffffffff,encrypted_response)
    print "[+] decrypted response: 0x%08x = %d"%(decrypted_response,decrypted_response)
    # Responses should decrypt to the same value across different mutated challenges of the same code/function.
    # Here you can detect code tampering: If the decrypted response is different than previous decrypted responses.
    print "[+] response time: %f ms"%response_time
    # Validate the response time here.
    # Check if the response time is lower or higher than the allowed/accepted response time thresholds.
    raw_input("[+] generate next challenge?")






