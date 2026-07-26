import os
import base64
import secrets
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage.file_manager import save_vault_state, load_vault_state

VAULT_DATA_FILE = "data/vault_state.json"

class MiniVaultCore:
    def __init__(self):
        self.dek = None         # DEK bản rõ lưu tạm trên RAM khi mở khóa
        self.is_locked = True   # Mặc định luôn khóa khi khởi động
        self.state_file = VAULT_DATA_FILE

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Dẫn xuất khóa AES 256-bit (32 bytes) từ Master Passphrase bằng Argon2id"""
        return hash_secret_raw(
            secret=passphrase.encode('utf-8'),
            salt=salt,
            time_cost=2,           # Số vòng lặp
            memory_cost=65536,     # Dùng ~64MB RAM
            parallelism=2,         # Số luồng
            hash_len=32,           # Độ dài khóa đầu ra (32 bytes = 256 bits)
            type=Type.ID
        )

    def init_vault(self, master_passphrase: str):
        """Khởi tạo Vault lần đầu tiên"""
        state = load_vault_state(self.state_file)
        if state is not None:
            raise ValueError("Vault đã được khởi tạo từ trước!")

        # 1. Tạo salt ngẫu nhiên (16 bytes) và dẫn xuất khóa
        salt = os.urandom(16)
        derived_key = self._derive_key(master_passphrase, salt)

        # 2. Sinh ngẫu nhiên Khóa mã hóa dữ liệu (DEK) - 32 bytes
        dek = secrets.token_bytes(32)

        # 3. Mã hóa DEK bằng AES-256-GCM sử dụng khóa vừa dẫn xuất
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12) # Nonce chuẩn cho GCM là 12 bytes
        # Ciphertext của AESGCM trong thư viện cryptography đã tự động nối kèm Authentication Tag ở cuối
        encrypted_dek = aesgcm.encrypt(nonce, dek, associated_data=None)

        # Trộn nonce vào cùng encrypted_dek để sau này có thể giải mã
        # Cấu trúc: nonce (12 bytes) + ciphertext + tag
        combined_encrypted_dek = nonce + encrypted_dek

        # 4. Ghi trạng thái ra file đĩa theo giao ước dữ liệu
        vault_data = {
            "kdf": "argon2id",
            "kdf_salt_b64": base64.b64encode(salt).decode('utf-8'),
            "encrypted_dek_b64": base64.b64encode(combined_encrypted_dek).decode('utf-8'),
        }
        
        save_vault_state(self.state_file, vault_data)
        print("Vault đã được khởi tạo thành công và đang ở trạng thái KHÓA.")

    def unlock_vault(self, master_passphrase: str):
        """Mở khóa Vault bằng Master Passphrase"""
        state = load_vault_state(self.state_file)
        if state is None:
            raise ValueError("Vault chưa được khởi tạo!")
        
        if not self.is_locked:
            print("Vault hiện đang không bị khóa.")
            return

        try:
            # 1. Đọc salt và encrypted_dek từ file
            salt = base64.b64decode(state["kdf_salt_b64"])
            combined_encrypted_dek = base64.b64decode(state["encrypted_dek_b64"])
            
            # 2. Tách nonce (12 bytes đầu) và dữ liệu mã hóa ra
            nonce = combined_encrypted_dek[:12]
            encrypted_dek = combined_encrypted_dek[12:]

            # 3. Dẫn xuất lại khóa từ passphrase người dùng nhập vào
            derived_key = self._derive_key(master_passphrase, salt)

            # 4. Cố gắng giải mã DEK
            aesgcm = AESGCM(derived_key)
            # Nếu sai mật khẩu, hàm decrypt sẽ quăng lỗi do GCM tag không khớp
            self.dek = aesgcm.decrypt(nonce, encrypted_dek, associated_data=None)
            
            # 5. Nếu giải mã thành công, đổi trạng thái
            self.is_locked = False
            print("Vault đã được MỞ KHÓA thành công!")

        except Exception:
            # Bắt lỗi chung chung để không tiết lộ chi tiết nếu sai mật khẩu hoặc file bị can thiệp
            raise ValueError("Lỗi: Không thể mở khóa Vault (Sai Master Passphrase hoặc dữ liệu bị hỏng).")
        
vault_obj = MiniVaultCore()