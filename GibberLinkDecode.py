import numpy as np
import wave
import json
import base64
import sys
import os
import subprocess
from cryptography.fernet import Fernet

# Configuration (match gibber.py)
SAMPLE_RATE = 44100  # Hz
DURATION = 0.1       # Seconds per bit
FREQ_0 = 1000        # Hz for bit 0
FREQ_1 = 2000        # Hz for bit 1

def run_openssl_command(args, input_data=None):
    """Run an OpenSSL command."""
    try:
        result = subprocess.run(args, input=input_data, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"OpenSSL error: {e.stderr}")
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
        print(f"Symmetric key decryption error: {e}")
        return None

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

def read_wav_file(filepath):
    """Read a WAV file and return the waveform."""
    try:
        with wave.open(filepath, 'rb') as wf:
            if wf.getframerate() != SAMPLE_RATE:
                print(f"Warning: WAV file sample rate {wf.getframerate()} Hz does not match expected {SAMPLE_RATE} Hz")
            channels = wf.getnchannels()
            frames = wf.readframes(wf.getnframes())
            waveform = np.frombuffer(frames, dtype=np.float32)
            if channels == 2:
                waveform = waveform.reshape(-1, 2).mean(axis=1)
            return waveform
    except Exception as e:
        print(f"Error reading WAV file: {e}")
        return None

def decode_wav_file(filepath, private_key_file=None, symmetric_key=None):
    """Decode a Gibberlink WAV file."""
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None
    waveform = read_wav_file(filepath)
    if waveform is None:
        return None
    cipher = Fernet(base64.urlsafe_b64encode(symmetric_key)) if symmetric_key else None
    decoded = decode_fsk(waveform, cipher=cipher)
    if isinstance(decoded, dict) and decoded.get("type") == "key_exchange" and private_key_file:
        encrypted_key = decoded.get("encrypted_key")
        if encrypted_key:
            symmetric_key = decrypt_symmetric_key(private_key_file, encrypted_key)
            if symmetric_key:
                print(f"Extracted symmetric key from {filepath}")
                return symmetric_key
    print(f"Decoded message from {filepath}:")
    print(json.dumps(decoded, indent=2) if isinstance(decoded, dict) else decoded)
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 decode_gibber.py <path_to_wav_file> [private_key_file]")
        sys.exit(1)
    private_key_file = sys.argv[2] if len(sys.argv) == 3 else None
    decode_wav_file(sys.argv[1], private_key_file=private_key_file)
