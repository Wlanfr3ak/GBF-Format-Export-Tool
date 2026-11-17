# -*- coding: utf-8 -*-
"""Brute-force KDF/cipher combos against GBF metadata block (offset 0x1000)."""
import hashlib, math, itertools, sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, Blowfish, DES3, ARC4, DES

# usage: re_try_decrypt.py <file.gbf> <password>
GBF = sys.argv[1] if len(sys.argv) > 1 else 'sample.gbf'
PW = (sys.argv[2] if len(sys.argv) > 2 else '').encode()

data = open(GBF, 'rb').read()
ct_meta = data[0x1000:0x1000+816]      # encrypted metadata (51*16)
ct_payload = data[0x2000:0x2000+1024]  # payload sample

# candidate salt regions from header
salts = {
    's00_20':  data[0x00:0x14],
    's18_24':  data[0x18:0x30],
    's18_20':  data[0x18:0x2c],
    's18_16':  data[0x18:0x28],
    's00_44':  data[0x00:0x2c],      # 44 bytes random region
    's5c_20':  data[0x5c:0x70],
    'sFE4_28': data[0xfe4:0x1000],
    'zero16':  b'\x00'*16,
}

def score(pt):
    if not pt: return -1
    # printable ascii ratio + bonus for known tokens
    pr = sum(1 for b in pt if 32 <= b < 127 or b in (9,10,13)) / len(pt)
    bonus = 0
    for tok in (b'Media', b'Channel', b'Event', b'Sample', b'<', b'Geutebr', b'Kamera', b'Cam'):
        if tok in pt: bonus += 2
    return pr + bonus

def try_dec(key, iv, cipher_name, ct):
    try:
        if cipher_name == 'AES-ECB':
            c = AES.new(key, AES.MODE_ECB)
        elif cipher_name == 'AES-CBC':
            c = AES.new(key, AES.MODE_CBC, iv=iv[:16])
        elif cipher_name == 'AES-CFB8':
            c = AES.new(key, AES.MODE_CFB, iv=iv[:16], segment_size=8)
        elif cipher_name == 'BF-ECB':
            c = Blowfish.new(key, Blowfish.MODE_ECB)
        elif cipher_name == 'BF-CBC':
            c = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv[:8])
        elif cipher_name == '3DES-ECB':
            c = DES3.new(key, DES3.MODE_ECB)
        elif cipher_name == '3DES-CBC':
            c = DES3.new(key, DES3.MODE_CBC, iv=iv[:8])
        elif cipher_name == 'RC4':
            c = ARC4.new(key)
        else:
            return None
        return c.decrypt(ct)
    except Exception:
        return None

def sha_iter(pw, salt, iters, dklen, alg='sha1'):
    # simple iterated sha: h=hash(pw+salt); repeat
    h = pw + salt
    for _ in range(iters):
        h = hashlib.new(alg, h).digest()
    out = h
    while len(out) < dklen:
        h = hashlib.new(alg, h + salt).digest()
        out += h
    return out[:dklen]

ivs = {
    'iv0':   b'\x00'*16,
    'iv18':  data[0x18:0x28],
    'iv00':  data[0x00:0x10],
    'iv5c':  data[0x5c:0x6c],
    'ivFE4': data[0xfe4:0xff4],
}

results = []
for sname, salt in salts.items():
    # PBKDF2 combos
    for alg in ('sha1', 'sha256', 'sha512', 'md5'):
        for dklen in (16, 24, 32):
            try:
                key = PBKDF2(PW, salt, dkLen=dklen, count=1000,
                             hmac_hash_module=getattr(hashlib, alg))
            except Exception:
                continue
            for klen in (16, 24, 32):
                k = key[:klen]
                for ivn, iv in ivs.items():
                    for cname in ('AES-CBC', 'AES-ECB'):
                        if klen > (32 if cname.startswith('AES') else 56): continue
                        pt = try_dec(k, iv, cname, ct_meta)
                        if pt is None: continue
                        sc = score(pt)
                        if sc > 0.5:
                            results.append((sc, sname, alg, dklen, klen, ivn, cname, pt[:64]))
                for cname in ('BF-ECB','BF-CBC','3DES-ECB','3DES-CBC','RC4'):
                    kk = k[:16] if cname.startswith('3DES') else k
                    pt = try_dec(kk, ivs['iv0'], cname, ct_meta)
                    if pt is None: continue
                    sc = score(pt)
                    if sc > 0.5:
                        results.append((sc, sname, alg, dklen, '-', 'iv0', cname, pt[:64]))
    # raw hash derivations (no salt, or sha(password), sha(salt+password))
    for desc, kmat in {
        'sha256(pw)': hashlib.sha256(PW).digest(),
        'sha256(salt+pw)': hashlib.sha256(salt+PW).digest(),
        'sha256(pw+salt)': hashlib.sha256(PW+salt).digest(),
        'md5(pw)*2': hashlib.md5(PW).digest()*2,
        'sha1(pw)': hashlib.sha1(PW).digest(),
    }.items():
        for klen in (16,24,32):
            k = (kmat*4)[:klen]
            for ivn, iv in ivs.items():
                for cname in ('AES-CBC','AES-ECB'):
                    pt = try_dec(k, iv, cname, ct_meta)
                    if pt is None: continue
                    sc = score(pt)
                    if sc > 0.5:
                        results.append((sc, sname, desc, '-', klen, ivn, cname, pt[:64]))

results.sort(key=lambda r: -r[0])
for r in results[:30]:
    print(f'score={r[0]:.2f} salt={r[1]} kdf={r[2]} dk={r[3]} klen={r[4]} iv={r[5]} cipher={r[6]}')
    print('   ', r[7])
print('total candidates >0.5:', len(results))
