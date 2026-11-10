"""Export the result tables and sources to one Excel workbook. Run from the project root:
    py scripts/05_export_excel.py

Input : output/tables/*.csv, data/clean/cleaning_log.csv, data/reference/sources.csv
Output: output/results.xlsx

The full cleaned data (2.5 million rows, 74 columns) is larger than an Excel sheet allows,
so the workbook holds the summary tables. Re-create the cleaned file with scripts/01_preprocess.py.
"""
from pathlib import Path

import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

T = Path("output/tables")
OUT = Path("output/results.xlsx")

OVERVIEW = [
    ("ชื่อ", "การตรวจจับการโจมตีเครือข่ายที่โมเดลไม่เคยเห็นมาก่อน (CIC-IDS2017)"),
    ("คำถาม", "traffic เป็นการโจมตีเท่าไรและแบบไหนบ่อยสุด? การโจมตีต่างจากปกติอย่างไร? โมเดลแยกการโจมตีได้ไหม? จับการโจมตีประเภทใหม่ได้ไหม?"),
    ("ข้อมูลต้นทาง", "CIC-IDS2017 (Sharafaldin, Lashkari, Ghorbani 2018) จาก Canadian Institute for Cybersecurity ผ่าน Kaggle mirror ดูชีต sources"),
    ("ข้อควรระวัง", "traffic มาจากห้องทดลองปี 2017 ไม่ใช่เครือข่ายจริง สัดส่วนการโจมตีสูงกว่าเครือข่ายจริงมาก"),
    ("ขนาดข้อมูล", "flow ทั้งหมด 2,830,743 รายการ หลังทำความสะอาด 2,520,798 รายการ 69 คุณสมบัติ"),
    ("ชีตในไฟล์นี้", "sources: แหล่งข้อมูลและลิงก์ | cleaning_log: ขั้นตอนการทำความสะอาด | attack_share: Q1 | label_by_day: Q1 แยกวัน | model_metrics: ผลโมเดล | recall_by_family: Q3 และ Q4 | feature_importance: คุณสมบัติที่โมเดลใช้มากสุด"),
    ("ไฟล์ข้อมูลเต็ม", "ไม่แนบ (ใหญ่เกิน Excel) สร้างใหม่ด้วย scripts/00_download.py และ scripts/01_preprocess.py"),
]

TABLE_SHEETS = [
    ("attack_share", "attack_share.csv", "Q1: จำนวนและสัดส่วน flow ของแต่ละประเภท"),
    ("label_by_day", "label_by_day.csv", "Q1: จำนวน flow แยกตามวันและประเภท"),
    ("model_metrics", "model_metrics.csv", "ผลโมเดล: PR-AUC, precision, recall, F1 ของการแบ่งทั้งสองแบบ"),
    ("recall_by_family", "recall_by_family.csv", "Q3 และ Q4: สัดส่วนการโจมตีแต่ละประเภทที่จับได้"),
    ("feature_importance", "feature_importance.csv", "15 คุณสมบัติที่โมเดลให้น้ำหนักมากสุด"),
]

HEADER_FILL = PatternFill("solid", fgColor="14213D")
HEADER_FONT = Font(bold=True, color="FFFFFF")


def write_sheet(writer, name, frame, note):
    """Note in row 1, table from row 3."""
    frame.to_excel(writer, sheet_name=name, index=False, startrow=2)
    ws = writer.sheets[name]
    ws["A1"] = note
    ws["A1"].font = Font(bold=True, size=12)
    for cell in ws[3]:
        if cell.value is not None:
            cell.fill, cell.font = HEADER_FILL, HEADER_FONT
            cell.alignment = Alignment(wrap_text=True, vertical="center")
    for col in range(1, ws.max_column + 1):
        letter = get_column_letter(col)
        width = max(len(str(c.value)) if c.value is not None else 0 for c in ws[letter][2:])
        ws.column_dimensions[letter].width = min(max(12, width + 2), 60)
    ws.freeze_panes = "A4"


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(OUT, engine="openpyxl") as writer:
        pd.DataFrame(OVERVIEW, columns=["หัวข้อ", "รายละเอียด"]).to_excel(writer, sheet_name="overview", index=False)
        ws = writer.sheets["overview"]
        ws.column_dimensions["A"].width = 18
        ws.column_dimensions["B"].width = 110
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")

        write_sheet(writer, "sources", pd.read_csv("data/reference/sources.csv"),
                    "แหล่งข้อมูลและลิงก์")
        write_sheet(writer, "cleaning_log", pd.read_csv("data/clean/cleaning_log.csv"),
                    "ขั้นตอนการทำความสะอาดข้อมูลและจำนวนแถวที่เหลือ")
        for sheet, file, note in TABLE_SHEETS:
            write_sheet(writer, sheet, pd.read_csv(T / file), note)

    wb = load_workbook(OUT)
    pct_cols = {"share_of_all_flows", "precision", "recall", "f1", "pr_auc", "roc_auc", "test_attack_share",
                "baseline_pr_auc", "importance", "cumulative"}
    for ws in wb.worksheets[2:]:
        headers = {c.value: c.column_letter for c in ws[3] if c.value}
        for name, letter in headers.items():
            if name in pct_cols:
                for cell in ws[letter][3:]:
                    cell.number_format = "0.00%"
            elif name in {"flows", "train_rows", "test_rows", "rows"}:
                for cell in ws[letter][3:]:
                    cell.number_format = "#,##0"
    wb.save(OUT)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
