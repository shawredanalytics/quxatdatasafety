from app import generate_blank_checklist_pdf
import os

try:
    pdf_bytes = generate_blank_checklist_pdf()
    with open("test_checklist.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("PDF generated successfully.")
    print(f"Size: {len(pdf_bytes)} bytes")
except Exception as e:
    print(f"Error generating PDF: {e}")
