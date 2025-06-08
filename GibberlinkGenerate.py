import numpy as np
import threading
import queue
import time
import json
import wave
import os
import base64
import subprocess
import secrets
from datetime import datetime
from cryptography.fernet import Fernet

# Configuration
SAMPLE_RATE = 44100  # Hz
DURATION = 0.1       # Seconds per bit
FREQ_0 = 1000        # Hz for bit 0
FREQ_1 = 2000        # Hz for bit 1
AUDIO_DIR = "audio"  # Directory for WAV files
KEY_DIR = "keys"     # Directory for key files
LOG_FILE = "gibberlink_log.txt"  # Log file
PLAY_AUDIO = False   # Disable playback

# Ensure directories exist
os.makedirs(AUDIO_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

# Shared queue for waveform exchange
message_queue = queue.Queue()

def run_openssl_command(args, input_data=None):
    """Run an OpenSSL command."""
    try:
        result = subprocess.run(args, input=input_data, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log_message("error", "System", f"OpenSSL error: {e.stderr}")
        return None

def generate_rsa_keys(client_name):
    """Generate RSA key pair using OpenSSL."""
    private_key_file = os.path.join(KEY_DIR, f"{client_name}_private.pem")
    public_key_file = os.path.join(KEY_DIR, f"{client_name}_public.pem")
    
    if not os.path.exists(private_key_file):
        run_openssl_command(["openssl", "genrsa", "-out", private_key_file, "2048"])
        print(f"{client_name} generated private key: {private_key_file}")
        log_message("key_generated", client_name, f"Private key saved: {private_key_file}")
    
    if not os.path.exists(public_key_file):
        run_openssl_command(["openssl", "rsa", "-in", private_key_file, "-pubout", "-out", public_key_file])
        print(f"{client_name} generated public key: {public_key_file}")
        log_message("key_generated", client_name, f"Public key saved: {public_key_file}")
    
    with open(public_key_file, 'r') as f:
        public_key = f.read()
    return private_key_file, public_key

def encrypt_symmetric_key(public_key_file, symmetric_key):
    """Encrypt symmetric key with RSA public key."""
    try:
        result = run_openssl_command([
            "openssl", "rsautl", "-encrypt", "-pubin", "-in", "/dev/stdin",
            "-out", "/dev/stdout", "-inkey", public_key_file
        ], input=base64.b64encode(symmetric_key).decode())
        return base64.b64encode(result.encode()).decode()
    except Exception as e:
        log_message("error", "System", f"Symmetric key encryption error: {e}")
        return None

def decrypt_symmetric_key(private_key_file, encrypted_key):
    """Decrypt symmetric key with RSA private key."""
    try:
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        result = run_openssl_command([
            "openssl", "rsautl", "-decrypt", "-in", "/dev/stdin",
            "-out", "/dev/stdout", "-inkey", private_key_file
        ], input=encrypted_key_bytes.decode())
        return base64.b64decode(result) if result else None
    except Exception as e:
        log_message("error", "System", f"Symmetric key decryption error: {e}")
        return None

def save_waveform(waveform, filename, channels=1):
    """Save waveform as a WAV file."""
    try:
        with wave.open(filename, 'wb') as wf:
            wf.setnchannels(channels)
            wf.setsampwidth(4)
            wf.setframerate(SAMPLE_RATE)
            if channels == 2:
                stereo_waveform = np.repeat(waveform[:, np.newaxis], 2, axis=1).ravel()
                wf.writeframes(stereo_waveform.tobytes())
            else:
                wf.writeframes(waveform.tobytes())
        print(f"Saved audio file: {filename}")
        log_message("saved_audio", "System", f"Waveform saved as {filename}")
    except Exception as e:
        print(f"Error saving waveform: {e}")
        log_message("error", "System", f"Waveform save error: {e}")

def encode_fsk(message, cipher=None):
    """Encode a message into an FSK waveform with smoother tones."""
    if isinstance(message, dict):
        message = json.dumps(message)
    if not isinstance(message, str):
        raise ValueError("Message must be a string or dict")
    if cipher:
        encrypted = cipher.encrypt(message.encode())
        message = base64.b64encode(encrypted).decode()
        log_message("encrypted", "System", f"Base64-encoded ciphertext: {message}")
    
    binary = ''.join(format(ord(c), '08b') for c in message)
    waveform = []
    for bit in binary:
        freq = FREQ_1 if bit == '1' else FREQ_0
        t = np.linspace(0, DURATION, int(SAMPLE_RATE * DURATION), False)
        # Frequency chirp: slide ±100 Hz
        chirp = np.linspace(freq - 100, freq + 100, len(t))
        signal = 0.5 * np.sin(2 * np.pi * chirp * t)
        # Amplitude envelope for smooth transitions
        envelope = np.exp(-4 * (t / DURATION - 0.5) ** 2)
        signal *= envelope
        # Add harmonic for richer sound
        harmonic = 0.1 * np.sin(2 * np.pi * (freq * 1.5) * t) * envelope
        signal += harmonic
        waveform.extend(signal)
    return np.array(waveform, dtype=np.float32)

def decode_fsk(waveform, cipher=None):
    """Decode an FSK waveform back to a message."""
    samples_per_bit = int(SAMPLE_RATE * DURATION)
    binary = ''
    for i in range(0, len(waveform), samples_per_bit):
        chunk = waveform[i:i + samples_per_bit]
        if len(chunk) < samples_per_bit:
            break
        fft = np.abs(np.fft.fft(chunk))
        freqs = np.fft.fftfreq(len(chunk), 1 / SAMPLE_RATE)
        peak_freq = abs(freqs[np.argmax(fft)])
        bit = '1' if peak_freq > (FREQ_0 + FREQ_1) / 2 else '0'
        binary += bit
    chars = [binary[i:i + 8] for i in range(0, len(binary), 8)]
    message = ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)
    if cipher:
        try:
            encrypted = base64.b64decode(message)
            decrypted = cipher.decrypt(encrypted).decode()
            return json.loads(decrypted)
        except Exception as e:
            print(f"Decryption error: {e}")
            return message
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        return message

def log_message(event, name, message):
    """Log message events to a file."""
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{datetime.now()} - {name} {event}: {message}\n")
    except Exception as e:
        print(f"Error logging message: {e}")

def client(name, send_messages, receive_queue, send_queue):
    """Client function for FSK-based encrypted communication."""
    print(f"{name} started at {datetime.now()}")
    log_message("started", name, "Client started")
    
    # Generate RSA keys
    private_key_file, public_key = generate_rsa_keys(name)
    
    # Send public key in handshake
    handshake = {"sender": name, "receiver": "other", "type": "handshake", "public_key": public_key}
    print(f"{name} sending handshake with public key (saved in {os.path.join(KEY_DIR, f'{name}_public.pem')}):")
    log_message("handshake_sent", name, handshake)
    waveform = encode_fsk(handshake)
    filename = os.path.join(AUDIO_DIR, f"{name}_handshake_{int(time.time())}.wav")
    save_waveform(waveform, filename, channels=1)
    if PLAY_AUDIO:
        print(f"{name} playing handshake audio...")
        play_waveform(waveform)
    send_queue.put(waveform)
    
    # Receive other client's public key and exchange symmetric key
    symmetric_key = None
    cipher = None
    other_public_key_file = os.path.join(KEY_DIR, f"other_{name}_public.pem")
    try:
        waveform = receive_queue.get(timeout=5.0)
        decoded = decode_fsk(waveform)
        print(f"{name} received handshake from {decoded.get('sender', 'unknown')}:")
        log_message("handshake_received", name, decoded)
        if isinstance(decoded, dict) and "public_key" in decoded:
            with open(other_public_key_file, 'w') as f:
                f.write(decoded["public_key"])
            if name == "Client1":
                symmetric_key = secrets.token_bytes(32)
                encrypted_key = encrypt_symmetric_key(other_public_key_file, symmetric_key)
                if encrypted_key:
                    key_exchange = {"sender": name, "receiver": "other", "type": "key_exchange", "encrypted_key": encrypted_key}
                    print(f"{name} sending encrypted symmetric key:")
                    log_message("key_exchange_sent", name, key_exchange)
                    waveform = encode_fsk(key_exchange)
                    filename = os.path.join(AUDIO_DIR, f"{name}_key_exchange_{int(time.time())}.wav")
                    save_waveform(waveform, filename, channels=1)
                    if PLAY_AUDIO:
                        print(f"{name} playing key exchange audio...")
                        play_waveform(waveform)
                    send_queue.put(waveform)
                    cipher = Fernet(base64.urlsafe_b64encode(symmetric_key))
            else:
                waveform = receive_queue.get(timeout=5.0)
                decoded_key = decode_fsk(waveform)
                print(f"{name} received key exchange from {decoded_key.get('sender', 'unknown')}:")
                log_message("key_exchange_received", name, decoded_key)
                if isinstance(decoded_key, dict) and "encrypted_key" in decoded_key:
                    symmetric_key = decrypt_symmetric_key(private_key_file, decoded_key["encrypted_key"])
                    if symmetric_key:
                        cipher = Fernet(base64.urlsafe_b64encode(symmetric_key))
        else:
            print(f"{name} invalid handshake received")
            log_message("error", name, "Invalid handshake received")
            return
    except queue.Empty:
        print(f"{name} handshake or key exchange timed out at {datetime.now()}")
        log_message("handshake_timeout", name, "Handshake or key exchange timed out")
        return
    
    if not cipher:
        print(f"{name} failed to establish encryption")
        log_message("error", name, "Failed to establish encryption")
        return
    
    print(f"\n{name} established secure connection with symmetric key")
    log_message("connection_established", name, "Secure connection with symmetric key")
    
    for idx, message in enumerate(send_messages):
        print(f"{name} encoding encrypted message: {message}")
        log_message("encoding", name, f"Plaintext: {message}")
        waveform = encode_fsk(message, cipher=cipher)
        filename = os.path.join(AUDIO_DIR, f"{name}_message_{idx}_{int(time.time())}.wav")
        save_waveform(waveform, filename, channels=1)
        if PLAY_AUDIO:
            print(f"{name} playing audio...")
            play_waveform(waveform)
        send_queue.put(waveform)
        print(f"{name} sent encrypted message at {datetime.now()}")
        log_message("sent", name, f"Encrypted message index {idx}")
        try:
            waveform = receive_queue.get(timeout=5.0)
            decoded = decode_fsk(waveform, cipher=cipher)
            print(f"{name} received and decrypted: {decoded} at {datetime.now()}")
            log_message("received_queue", name, f"Decrypted: {decoded}")
        except queue.Empty:
            print(f"{name} timed out waiting for message at {datetime.now()}")
            log_message("timeout", name, "Timed out waiting for message")
        time.sleep(1)

def main():
    client1_messages = [
        {"sender": "AI_1", "receiver": "AI_2", "text": "Hello, AI_2! Ready to book a hotel?"},
        {"sender": "AI_1", "receiver": "AI_2", "text": "How about London on June 10?"},
        {"sender": "AI_1", "receiver": "AI_2", "text": "Prefer a 4-star hotel near downtown."},
        {"sender": "AI_1", "receiver": "AI_2", "text": "Can you check availability for 2 rooms?"}
    ]
    client2_messages = [
        {"sender": "AI_2", "receiver": "AI_1", "text": "Hi, AI_1! Yes, let's book it."},
        {"sender": "AI_2", "receiver": "AI_1", "text": "London sounds great! Confirming June 10."},
        {"sender": "AI_2", "receiver": "AI_1", "text": "Found a 4-star hotel, The Grand, near Trafalgar Square."},
        {"sender": "AI_2", "receiver": "AI_1", "text": "2 rooms available. Shall I reserve?"}
    ]
    queue1 = queue.Queue()
    queue2 = queue.Queue()
    client1_thread = threading.Thread(target=client, args=("Client1", client1_messages, queue1, queue2))
    client2_thread = threading.Thread(target=client, args=("Client2", client2_messages, queue2, queue1))
    print("Starting secure Gibberlink communication...")
    client1_thread.start()
    client2_thread.start()
    client1_thread.join()
    client2_thread.join()
    print(f"Chat session ended at {datetime.now()}")
    log_message("ended", "Session", "Chat session ended")

if __name__ == "__main__":
    main()
