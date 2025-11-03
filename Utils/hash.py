import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    return hashed
def verify(password, hashed):
    check = bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    return check
