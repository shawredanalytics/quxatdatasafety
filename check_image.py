from PIL import Image
import os

if os.path.exists("poster_ref.png"):
    try:
        img = Image.open("poster_ref.png")
        print(f"Size: {img.size}")
        print(f"Format: {img.format}")
    except Exception as e:
        print(f"Error: {e}")
else:
    print("File not found")
