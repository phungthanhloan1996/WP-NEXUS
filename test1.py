import requests
import re

def compare_methods():
    url = "https://crt.sh/?q=.gov.vn&output=json"
    print("[*] Đang query crt.sh...")
    
    try:
        r = requests.get(url, timeout=30)
        print(f"[*] Status code: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            print(f"[*] Nhận được {len(data)} entries từ crt.sh")
            
            # PHƯƠNG PHÁP CŨ (≤4)
            old_method = []
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    name = name.lower().replace('*.', '')
                    # Xử lý \n ngay lập tức
                    if '\n' in name:
                        for d in name.split('\n'):
                            d = d.strip()
                            if d and len(d.split('.')) <= 4:
                                old_method.append(d)
                    else:
                        if name and len(name.split('.')) <= 4:
                            old_method.append(name)
            
            # PHƯƠNG PHÁP MỚI (≤5 với xử lý \n riêng)
            new_method = []
            for entry in data:
                name = entry.get('name_value', '').lower()
                if '\n' in name:
                    for d in name.split('\n'):
                        d = d.strip().replace('*.', '')
                        if d and len(d.split('.')) <= 5:
                            new_method.append(d)
                else:
                    name = name.replace('*.', '')
                    if name and len(name.split('.')) <= 5:
                        new_method.append(name)
            
            print(f"\n=== KẾT QUẢ ===")
            print(f"Bản cũ (≤4): {len(set(old_method))} unique domain")
            print(f"Bản mới (≤5): {len(set(new_method))} unique domain")
            
            # Tìm www.nisci.gov.vn
            www_nisci = 'www.nisci.gov.vn'
            in_old = www_nisci in old_method or www_nisci in [d.replace('*.', '') for d in old_method]
            in_new = www_nisci in new_method or www_nisci in [d.replace('*.', '') for d in new_method]
            
            print(f"\nCó '{www_nisci}' trong:")
            print(f"  - Bản cũ: {'✅ CÓ' if in_old else '❌ KHÔNG'}")
            print(f"  - Bản mới: {'✅ CÓ' if in_new else '❌ KHÔNG'}")
            
            # Kiểm tra thực tế
            print(f"\n[*] Kiểm tra thủ công trong 10 domain đầu:")
            for i, entry in enumerate(data[:10]):
                name = entry.get('name_value', '')
                print(f"  {i+1}. {name}")
                
        else:
            print(f"[!] Lỗi HTTP: {r.status_code}")
            
    except Exception as e:
        print(f"[!] Lỗi: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    compare_methods()