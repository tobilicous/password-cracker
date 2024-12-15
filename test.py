import hashlib
import itertools
import time
import multiprocessing

# Function to generate MD5 hash
def md5_hash(passwords):
    """
    Hashes passwords using hashlib.
    """
    try:
        return [hashlib.md5(p.encode()).hexdigest() for p in passwords]
    except Exception as e:
        print(f"[ERROR] md5_hash failed: {e}")
        raise

# Function to load hashes from a file
def load_hashes(file_name):
    with open(file_name, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Worker function for multiprocessing
def crack_worker(hashes, charset, length, batch_size, start_time):
    cracked = {}
    hashes = set(hashes)  # Convert to set for faster lookups

    # Generate passwords in batches
    for batch_start in range(0, len(charset) ** length, batch_size):
        passwords = [
            ''.join(p) for p in itertools.islice(
                itertools.product(charset, repeat=length), batch_start, batch_start + batch_size
            )
        ]

        # Hash passwords
        hashed_batch = md5_hash(passwords)

        # Check for matches
        for password, hashed in zip(passwords, hashed_batch):
            if hashed in hashes:
                elapsed_time = time.time() - start_time
                cracked[hashed] = (password, elapsed_time)
                print(f"[DEBUG] Found: {password} (Time: {elapsed_time:.2f}s)")
                hashes.remove(hashed)  # Remove found hash to reduce search space

    return cracked

# Helper function for multiprocessing
def process_task(args):
    return crack_worker(*args)

# Function to crack hashes using multiprocessing
def crack_hashes(hashes, max_length=8):
    cracked = {}
    start_time = time.time()
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'

    print("[DEBUG] Starting multiprocessing cracking process...")

    try:
        # Use a multiprocessing pool
        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
            for length in range(1, max_length + 1):
                print(f"[DEBUG] Cracking passwords of length {length}...")

                # Define batch size
                batch_size = 10000

                # Prepare tasks for workers
                tasks = [
                    (hashes, charset, length, batch_size, start_time)
                    for _ in range(multiprocessing.cpu_count())
                ]

                # Process tasks
                for result in pool.imap_unordered(process_task, tasks):
                    cracked.update(result)

                    # Stop if all hashes are cracked
                    if len(cracked) == len(hashes):
                        print("[DEBUG] All hashes cracked.")
                        return cracked

    except KeyboardInterrupt:
        print("[INFO] Cracking process interrupted. Returning results so far...")
        return cracked

    return cracked

if __name__ == "__main__":
    # Load the hashes
    hashes = load_hashes("hashes.txt")

    # Crack the hashes
    print("Starting to crack hashes using multiprocessing...")
    cracked_passwords = crack_hashes(hashes, max_length=6)  # Reduce max_length for testing

    # Output results
    print("\nCracked Passwords:")
    for hash_value, (password, time_taken) in cracked_passwords.items():
        print(f"Hash: {hash_value}\tPassword: {password}\tTime: {time_taken:.2f} seconds")
