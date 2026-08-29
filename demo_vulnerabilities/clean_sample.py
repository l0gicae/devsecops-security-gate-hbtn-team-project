"""
=============================================================================
 🛡️ TƏMİZ VƏ TƏHLÜKƏSİZ KOD (Remediated Clean Code)
-----------------------------------------------------------------------------
 QEYD: Bu fayl eyni funksionallığın DevSecOps standartlarına uyğun,
       təhlükəsiz və sızmasız şəkildə yazılmış versiyasıdır.
=============================================================================
"""

import os
import sqlite3
import ast
import subprocess

# 1. ✅ Açar və Şifrələr Mühit Dəyişənlərindən (Environment Variables) oxunur
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")

def get_user_profile(user_id):
    """2. ✅ PARAMETRLƏŞDİRİLMİŞ TƏHLÜKƏSİZ SQL SORĞUSU (No SQL Injection)"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Parametrləşdirilmiş sorğu SQL Injection-ın qarşısını alır
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

def calculate_expression(user_math_input):
    """3. ✅ TƏHLÜKƏSİZ LİTERAL ANALİZİ (No RCE)"""
    try:
        # eval() əvəzinə yalnız təhlükəsiz strukturları qəbul edən parser
        result = ast.literal_eval(user_math_input)
        return result
    except (ValueError, SyntaxError):
        return 0

def ping_server(hostname):
    """4. ✅ SHELL=FALSE İLƏ TƏHLÜKƏSİZ SUBPROCESS İCRASI"""
    # shell=True və os.system əvəzinə arqumentlər siyahı kimi ötürülür
    subprocess.run(["ping", "-n", "1", hostname], check=True, capture_output=True)

if __name__ == "__main__":
    print("Secure server logic ready.")
