import shutil
import os

src = r"C:\Users\MANIKUMAR\Desktop\QuXAT Ai - Platform Development\QuXAT Data Security.png"
dst = r"C:\Users\MANIKUMAR\Desktop\QuXAT Data Safety\quxatdatasafety\poster_ref.png"

if os.path.exists(src):
    print(f"Copying {src} to {dst}")
    shutil.copy(src, dst)
    print("Success")
else:
    print(f"Source file not found: {src}")
