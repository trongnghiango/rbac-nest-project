import os
import re

# ==============================================================================
# CẤU HÌNH PATH
# ==============================================================================
ROOT_DIR = os.getcwd()

# 1. Các file rác cần xóa vĩnh viễn (Vì đã có bản thay thế ở dental-treatment)
FILES_TO_DELETE = [
    "src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts",
    "src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts.bak",
    "src/database/schema/ortho.schema.old.ts",
    "src/modules/dental/application/services/dental.service.ts.deleted_bak"
]

# 2. File Repository MỚI cần làm sạch logic cũ
REPO_FILE = "src/modules/dental-treatment/infrastructure/persistence/repositories/drizzle-cases.repository.ts"

# ==============================================================================
# LOGIC LÀM SẠCH REPOSITORY
# ==============================================================================

def clean_repository_file():
    print(f"🧹 Cleaning Repository Logic: {REPO_FILE}")
    full_path = os.path.join(ROOT_DIR, REPO_FILE)

    if not os.path.exists(full_path):
        print("❌ File not found!")
        return

    with open(full_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Xóa hàm createFullCase (Sử dụng Regex matching cơ bản để xóa khối hàm)
    # Tìm từ "async createFullCase" đến "return String(newCase.id);\n    };\n\n    if (tx) return runInTx(tx);\n    return this.db.transaction(runInTx);\n  }"
    # Cách đơn giản hơn: Filter dòng.

    lines = content.split('\n')
    new_lines = []
    is_deleting = False
    brace_count = 0

    for line in lines:
        # Phát hiện bắt đầu hàm legacy
        if "async createFullCase" in line or "async saveSteps" in line:
            is_deleting = True
            # print(f"   - Removing legacy method start: {line.strip()}")

        if is_deleting:
            brace_count += line.count('{')
            brace_count -= line.count('}')
            # Nếu brace_count về 0 nghĩa là hết hàm
            if brace_count == 0:
                is_deleting = False
            continue # Bỏ qua dòng này (không thêm vào new_lines)

        # Xóa các import thừa thãi
        if "ClinicInput" in line or "DentistInput" in line or "PatientInput" in line or "FullCaseInput" in line:
            # Chỉ xóa nếu nó nằm trong khối import
            if "import" in line and "from" not in line: # Dòng liệt kê import
                 line = line.replace("ClinicInput,", "").replace("DentistInput,", "").replace("PatientInput,", "").replace("FullCaseInput,", "")
            elif "import" not in line: # Dòng sử dụng type (nếu sót)
                 continue

        new_lines.append(line)

    cleaned_content = '\n'.join(new_lines)

    # Xóa khoảng trắng thừa do việc xóa dòng tạo ra
    cleaned_content = re.sub(r'\n{3,}', '\n\n', cleaned_content)

    with open(full_path, 'w', encoding='utf-8') as f:
        f.write(cleaned_content)
    print("✅ Repository clean. Removed 'createFullCase' and 'saveSteps'.")

# ==============================================================================
# LOGIC XÓA FILE
# ==============================================================================

def delete_garbage_files():
    print("\n🗑️  Deleting Garbage Files...")
    for rel_path in FILES_TO_DELETE:
        path_to_del = os.path.join(ROOT_DIR, rel_path)
        if os.path.exists(path_to_del):
            try:
                os.remove(path_to_del)
                print(f"✅ Deleted: {rel_path}")
            except Exception as e:
                print(f"❌ Error deleting {rel_path}: {e}")
        else:
            print(f"ℹ️  Already gone: {rel_path}")

# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":
    print("🚀 FINAL PROJECT CLEANUP...\n")
    clean_repository_file()
    delete_garbage_files()
    print("\n🎉 PROJECT IS NOW 100% CLEAN & PRO!")