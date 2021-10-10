import hashlib

def input_functon():
    password =input("Enter your password : ").encode()
    return password

def md5_hash(password):
    md5 = hashlib.md5(password)
    return md5.hexdigest()

def sha1_hash(passowrd):
    sha1 = hashlib.sha1(passowrd)
    return sha1.hexdigest()

def sha224_hash(password):
    sha224 = hashlib.sha224(password)
    return sha224.hexdigest()

def sha256_hash(password):
    sha256 = hashlib.sha224(password)
    return sha256.hexdigest()

def sha384_hash(password):
    sha384 = hashlib.sha224(password)
    return sha384.hexdigest()

def sha512_hash(password):
    sha512 = hashlib.sha224(password)
    return sha512.hexdigest()

passowrd = input_functon()

md5 = md5_hash(passowrd)
sha1 = sha1_hash(passowrd)
sha224 = sha224_hash(passowrd)
sha256 = sha256_hash(passowrd)
sha384 = sha384_hash(passowrd)
sha512 = sha512_hash(passowrd)

print(f'md5_hash : {md5}')
print(f'sha1_hash : {sha1}')
print(f'sha224_hash : {sha224}')
print(f'sha256_hash : {sha256}')
print(f'sha384_hash : {sha384}')
print(f'sha512_hash : {sha512}')