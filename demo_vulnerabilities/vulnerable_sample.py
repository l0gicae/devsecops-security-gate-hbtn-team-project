"""
=============================================================================
 ⚠️ NÜMUNƏ ZƏİF KOD (Vulnerable Sample for Live Demo)
-----------------------------------------------------------------------------
 QEYD: Bu fayl DevSecOps Təhlükəsizlik Qapısının aşkarlama və bloklama
       qabiliyyətini nümayiş etdirmək üçün bilərəkdən zəifliklərlə yazılmışdır.
=============================================================================
"""

import os
import sqlite3

# 1. 🚨 SIZMIŞ GİZLİ AÇARLAR (Leaked Secret Keys)
OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "SuperSecretPassword123!"

def get_user_profile(user_id):
    """2. 🚨 SQL INJECTION ZƏİFLİYİ"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Təhlükəli string formatlaşdırma - SQL Injection-a yol açır
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def calculate_expression(user_math_input):
    """3. 🚨 DİNAMİK KOD İCRASI (Remote Code Execution - RCE Riski)"""
    # Təhlükəli eval() istifadəsi
    result = eval(user_math_input)
    return result

def ping_server(hostname):
    """4. 🚨 KOMANDA İNYEKSİYASI (Command Injection)"""
    # Təhlükəli os.system istifadəsi
    os.system(f"ping -c 1 {hostname}")

if __name__ == "__main__":
    print("Vulnerable server logic ready.")
