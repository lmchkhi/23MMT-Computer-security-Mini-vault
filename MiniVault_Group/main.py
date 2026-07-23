from src.core.vault import MiniVaultCore

def main():
    # Tạo một instance của Vault Core
    vault = MiniVaultCore()
    
    print("--- TRẠNG THÁI BAN ĐẦU ---")
    print(f"Vault đang bị khóa: {vault.is_locked}")
    print(f"DEK trong bộ nhớ: {vault.dek}\n")

    # Kịch bản 1: Khởi tạo Vault lần đầu
    # (Nếu file data/vault_state.json đã tồn tại, bước này sẽ báo lỗi, 
    # bạn có thể xóa file json đó đi để test lại từ đầu)
    print("--- KHỞI TẠO VAULT ---")
    try:
        vault.init_vault("MatKhauSieuKho123!")
    except Exception as e:
        print(e)
    print()

    # Kịch bản 2: Mở khóa với mật khẩu SAI
    print("--- TEST SAI MẬT KHẨU ---")
    try:
        vault.unlock_vault("MatKhauSai")
    except Exception as e:
        print(e)
    print()

    # Kịch bản 3: Mở khóa với mật khẩu ĐÚNG
    print("--- TEST ĐÚNG MẬT KHẨU ---")
    try:
        vault.unlock_vault("MatKhauSieuKho123!")
        print(f"Trạng thái khóa hiện tại: {vault.is_locked}")
        print(f"DEK đã được giải mã đưa vào RAM: {vault.dek.hex()}")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()