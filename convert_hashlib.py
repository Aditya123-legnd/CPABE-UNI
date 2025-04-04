import hashlib

def hash_password(password):
    return hashlib.sha256('IT123'.encode()).hexdigest()

# Example usage
plain_password = "placementoff123"
hashed_password = hash_password(plain_password)
print("SHA-256 Hash:", hashed_password)