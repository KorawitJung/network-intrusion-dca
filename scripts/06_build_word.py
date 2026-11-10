"""Write the Thai methodology document as Word. Run from the project root: py scripts/06_build_word.py

Input : data/reference/sources.csv, data/clean/cleaning_log.csv and the tables in output/tables/
Output: output/METHODOLOGY_TH.docx (copied to docs/ by 04_dashboard.py)
"""
from pathlib import Path

import pandas as pd
from docx import Document
from docx.oxml.ns import qn
from docx.shared import Pt

OUT = Path("output/METHODOLOGY_TH.docx")
T = Path("output/tables")

share = pd.read_csv(T / "attack_share.csv")
metrics = pd.read_csv(T / "model_metrics.csv").set_index("evaluation")
recall = pd.read_csv(T / "recall_by_family.csv")
sources = pd.read_csv("data/reference/sources.csv")
clean_log = pd.read_csv("data/clean/cleaning_log.csv")
rec = recall.pivot(index="attack_family", columns="evaluation", values="recall")
RANDOM, CROSS = "random split", "train Mon-Thu, test Fri"
benign = float(share.loc[share["attack_family"] == "Benign", "share_of_all_flows"].iloc[0])

doc = Document()
style = doc.styles["Normal"]
style.font.name = "Leelawadee UI"
style.font.size = Pt(12)
style.element.rPr.rFonts.set(qn("w:eastAsia"), "Leelawadee UI")
style.paragraph_format.space_after = Pt(6)


def h(text, level=1):
    doc.add_heading(text, level=level)


def para(text):
    doc.add_paragraph(text)


def bullets(items):
    for it in items:
        doc.add_paragraph(it, style="List Bullet")


def table(headers, rows):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1"
    for i, head in enumerate(headers):
        t.rows[0].cells[i].text = head
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = str(v)
    doc.add_paragraph()


doc.add_heading("การตรวจจับการโจมตีเครือข่ายที่โมเดลไม่เคยเห็นมาก่อน", 0)
para("คำอธิบายวิธีการทำงานทั้งหมด: การเก็บข้อมูล การทำความสะอาด การวิเคราะห์ และการสร้าง dashboard")
para("ข้อมูลที่ใช้: CIC-IDS2017 จาก Canadian Institute for Cybersecurity ดูหัวข้อ 2 สำหรับลิงก์และการอ้างอิง")

h("1. คำถามของโปรเจกต์")
bullets([
    "คำถามที่ 1: traffic เป็นการโจมตีเท่าไร และประเภทไหนพบบ่อยที่สุด",
    "คำถามที่ 2: traffic ของการโจมตีต่างจาก traffic ปกติอย่างไร",
    "คำถามที่ 3: โมเดลแยกการโจมตีออกจาก traffic ปกติได้หรือไม่",
    "คำถามที่ 4: โมเดลจับการโจมตีประเภทที่ไม่เคยเห็นได้หรือไม่",
])
para("ประเด็นหลักของโปรเจกต์คือ คะแนนที่ดูดีจากการแบ่งข้อมูลแบบสุ่มอาจทำให้เข้าใจผิดว่าโมเดลป้องกันการโจมตีใหม่ได้ดี")

h("2. แหล่งข้อมูล")
rows = [(r["name"], r["role"], r["url"], r["licence_note"]) for _, r in sources.iterrows()]
table(["ชื่อ", "บทบาท", "ลิงก์", "หมายเหตุ"], rows)
para("ข้อควรระวัง: ข้อมูลมาจากห้องทดลองปี 2017 ตารางการโจมตีถูกกำหนดไว้ล่วงหน้า สัดส่วนการโจมตีจึงสูงกว่าเครือข่ายจริงมาก ผลสะท้อนห้องทดลอง ไม่ใช่เครือข่ายที่ใช้งานอยู่")

h("3. การเก็บข้อมูล")
para("scripts/00_download.py ดาวน์โหลดไฟล์ CSV แปดไฟล์จาก Kaggle mirror ไปยัง data/raw/ ไฟล์ดิบไม่ถูกเก็บใน GitHub เพราะมีขนาดประมาณ 1 GB")
para("แต่ละไฟล์คือการจับ traffic หนึ่งวัน (จันทร์ถึงศุกร์) และมีป้ายกำกับของแต่ละ flow เช่น BENIGN, DDoS, PortScan")

h("4. การทำความสะอาดข้อมูล")
para("scripts/01_preprocess.py ทำตามขั้นตอนนี้ และบันทึกจำนวนแถวไว้ใน data/clean/cleaning_log.csv")
table(["ขั้นตอน", "กฎ"], [
    ("รวมไฟล์รายวัน", "เพิ่มคอลัมน์ day จากชื่อไฟล์ และ source_file เพื่อให้ตรวจย้อนได้"),
    ("ลบคอลัมน์ที่ซ้ำ", "เช่น Fwd Header Length.1 ที่เกิดจากชื่อซ้ำ"),
    ("แก้ป้ายกำกับ", "แปลงอักขระที่เข้ารหัสผิดในป้าย และจัดกลุ่มเป็นประเภทการโจมตี"),
    ("ลบค่าที่ไม่ถูกต้อง", "ค่า Inf, NaN หรือไม่ใช่ตัวเลข"),
    ("ลบคอลัมน์ค่าคงที่", "คอลัมน์ที่มีค่าเดียวทั้งไฟล์ไม่ช่วยแยกการโจมตี"),
    ("ลบ flow ซ้ำ", "flow ที่เหมือนกันทุกคุณสมบัติและป้ายกำกับ"),
    ("สร้างตัวอย่างสำหรับ EDA", "สุ่มไม่เกิน 5,000 flow ต่อป้าย เพื่อให้กราฟอ่านได้"),
])
rows = [(r["step"], f"{r['rows']:,}") for _, r in clean_log.iterrows()]
table(["ขั้นตอน", "จำนวนแถวหลังขั้นตอน"], rows)

h("5. วิธีวิเคราะห์")
bullets([
    "คำถามที่ 1 และ 2: นับ flow แยกตามประเภท และวาดกราฟกล่องของคุณสมบัติสี่ตัวเทียบกับ traffic ปกติ",
    "คำถามที่ 3: ใช้ Random Forest จำนวน 100 ต้น ถ่วงน้ำหนักชั้นที่พบน้อย แบ่งข้อมูลแบบสุ่ม 70/30",
    "คำถามที่ 4: ฝึกด้วยวันจันทร์ถึงพฤหัสบดี ทดสอบด้วยวันศุกร์ ซึ่งมีประเภทการโจมตี (botnet, port scan, DDoS) ที่ไม่เกิดก่อนหน้า",
    "Destination Port ไม่ถูกใช้ในโมเดล เพราะในห้องทดลองระบุบริการที่ถูกโจมตี มากกว่าพฤติกรรมของ flow",
])

h("6. ผลลัพธ์")
para(f"ใน traffic ทั้งหมด {benign:.1%} เป็นปกติ และ {1 - benign:.1%} เป็นการโจมตี ส่วนใหญ่เป็น DoS, DDoS และ PortScan")
table(["การทดสอบ", "จำนวนแถวฝึก", "จำนวนแถวทดสอบ", "PR-AUC", "Precision", "Recall"], [
    (r.evaluation, f"{int(r.train_rows):,}", f"{int(r.test_rows):,}", f"{r.pr_auc:.3f}", f"{r.precision:.3f}", f"{r.recall:.3f}")
    for r in metrics.reset_index().itertuples()
])
rows = []
for fam in rec.index:
    rows.append((fam,
                 f"{rec.loc[fam, RANDOM]:.1%}" if pd.notna(rec.loc[fam, RANDOM]) else "-",
                 f"{rec.loc[fam, CROSS]:.1%}" if CROSS in rec and pd.notna(rec.loc[fam, CROSS]) else "ไม่มีในการทดสอบ"))
table(["ประเภทการโจมตี", "จับได้ (สุ่ม)", "จับได้ (ฝึกจันทร์-พฤหัส ทดสอบศุกร์)"], rows)
para(f"การทดสอบแบบสุ่มจับการโจมตีได้ {metrics.loc[RANDOM, 'recall']:.1%} แต่เมื่อทดสอบด้วยวันศุกร์ซึ่งเป็นการโจมตีประเภทใหม่ จับได้เพียง {metrics.loc[CROSS, 'recall']:.1%} โดยที่ความแม่นยำของการแจ้งเตือนยังสูงถึง {metrics.loc[CROSS, 'precision']:.1%} หมายความว่าโมเดลแจ้งเตือนได้ถูกต้อง แต่ไม่เห็นการโจมตีที่ไม่เคยเรียนรู้")

h("7. ข้อจำกัด")
bullets([
    "traffic มาจากห้องทดลองปี 2017 การโจมตีและ traffic ปกติต่างจากเครือข่ายปัจจุบัน",
    "มีการวิจารณ์ว่าไฟล์ต้นฉบับมีข้อผิดพลาดของป้ายกำกับและการสร้าง flow โครงการนี้ใช้ไฟล์ตามที่แจกจ่าย",
    "วันศุกร์มีการโจมตีที่ไม่เกิดในวันอื่น การทดสอบข้ามวันจึงวัดการจับประเภทใหม่ ไม่ใช่การจับการโจมตีเดิมในเวลาต่อมา",
    "ตัวอย่างสำหรับ EDA ถูกสุ่มให้สมดุลตามป้าย จึงไม่สะท้อนสัดส่วนจริง",
])

h("8. วิธีรันซ้ำ")
para("ติดตั้ง: pip install -r requirements.txt แล้วรันตามลำดับ:")
bullets([
    "py scripts/00_download.py",
    "py scripts/01_preprocess.py",
    "py scripts/02_eda.py",
    "py scripts/03_model.py",
    "py scripts/04_dashboard.py",
    "py scripts/05_export_excel.py",
    "py scripts/06_build_word.py",
])

h("9. ไฟล์ในโปรเจกต์")
table(["ไฟล์", "เนื้อหา"], [
    ("docs/index.html", "Dashboard ภาษาอังกฤษ"),
    ("docs/th.html", "Dashboard ภาษาไทย"),
    ("output/results.xlsx", "ตารางผลลัพธ์และแหล่งข้อมูลใน Excel"),
    ("output/METHODOLOGY_TH.docx", "เอกสารนี้"),
    ("output/png/", "กราฟแบบภาพนิ่ง"),
])

OUT.parent.mkdir(parents=True, exist_ok=True)
doc.save(OUT)
print("wrote", OUT)
