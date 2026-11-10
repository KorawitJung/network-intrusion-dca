"""Build the dashboards in English and Thai. Run from the project root: py scripts/04_dashboard.py

Input : data/clean/cicids2017_sample.csv and the tables in output/tables/
Output: docs/index.html (English), docs/th.html (ภาษาไทย). GitHub Pages serves both from /docs.

All numbers in the text are computed from the tables when the script runs, so the text
cannot drift from the charts. Each language has its own wording in TEXT below.
"""
import shutil
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
from plotly.offline import get_plotlyjs_version
from plotly.subplots import make_subplots

RED, BLUE, GREY = "#c1121f", "#2a6f97", "#b8bcc2"
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
FAMILY_COLORS = {
    "DoS": "#c1121f", "DDoS": "#f4a259", "PortScan": "#6a4c93", "Brute force": "#2a9d8f",
    "Web attack": "#e76f51", "Botnet": "#264653", "Infiltration": "#8ab17d", "Other": "#b8bcc2",
}
FAMILY_TH = {
    "Benign": "ปกติ", "DoS": "DoS (ท่วมเซิร์ฟเวอร์)", "DDoS": "DDoS (ท่วมจากหลายเครื่อง)",
    "PortScan": "สแกนพอร์ต", "Brute force": "เดารหัสผ่าน", "Web attack": "โจมตีเว็บ",
    "Botnet": "บอตเน็ต", "Infiltration": "ซึมเข้าภายใน", "Other": "อื่น ๆ",
}
DAY_TH = {"Monday": "จันทร์", "Tuesday": "อังคาร", "Wednesday": "พุธ", "Thursday": "พฤหัสบดี", "Friday": "ศุกร์"}
T = Path("output/tables")

share = pd.read_csv(T / "attack_share.csv").sort_values("flows")
by_day = pd.read_csv(T / "label_by_day.csv")
recall = pd.read_csv(T / "recall_by_family.csv")
metrics = pd.read_csv(T / "model_metrics.csv").set_index("evaluation")
sample = pd.read_csv("data/clean/cicids2017_sample.csv", low_memory=False)

RANDOM, CROSS = "random split", "train Mon-Thu, test Fri"
has_cross = CROSS in metrics.index
total = int(share["flows"].sum())
benign_share = float(share.loc[share["attack_family"] == "Benign", "share_of_all_flows"].iloc[0])
attacks = share[share["attack_family"] != "Benign"].sort_values("flows", ascending=False)
top3 = attacks.head(3)
small = attacks.iloc[3:]
pivot = (by_day[by_day["attack_family"] != "Benign"]
         .pivot_table(index="day", columns="attack_family", values="flows", aggfunc="sum", fill_value=0)
         .reindex([d for d in DAYS if d in set(by_day["day"])], fill_value=0))
quiet_days = [d for d in pivot.index if pivot.loc[d].sum() == 0]
rec = recall.pivot(index="attack_family", columns="evaluation", values="recall")
flows_by = recall.pivot(index="attack_family", columns="evaluation", values="flows")
weakest = rec[RANDOM][flows_by[RANDOM] >= 100].idxmin()
cross_order = rec[CROSS].dropna().sort_values(ascending=False) if has_cross else pd.Series(dtype=float)
dur = sample.assign(v=sample["Flow Duration"].abs() + 1).groupby("attack_family")["v"].median()


def pct(v):
    """Whole percent, except near 100% where rounding would claim a perfect score."""
    return f"{v:.2%}" if 0.995 <= v < 1 else f"{v:.0%}"


def micro(us):
    return f"{us / 1e6:.2f} seconds" if us >= 1e6 else f"{us / 1e3:.2f} milliseconds"


N = dict(
    total=f"{total:,}", attack=f"{1 - benign_share:.1%}", benign=f"{benign_share:.1%}",
    one_in=str(round(1 / (1 - benign_share))),
    rand_recall=f"{metrics.loc[RANDOM, 'recall']:.1%}", rand_prec=f"{metrics.loc[RANDOM, 'precision']:.1%}",
    weakest=weakest, weakest_rate=f"{rec.loc[weakest, RANDOM]:.0%}",
    cross_recall=f"{metrics.loc[CROSS, 'recall']:.1%}" if has_cross else "",
    cross_prec=f"{metrics.loc[CROSS, 'precision']:.1%}" if has_cross else "",
    dur_benign=micro(dur["Benign"]), dur_ps=micro(dur["PortScan"]),
    dur_dos=f"{dur['DoS'] / 1e6:.0f} seconds",
    top3=", ".join(f"{r.attack_family} ({r.share_of_all_flows:.1%})" for r in top3.itertuples()),
    small=", ".join(small["attack_family"]), small_max=f"{small['share_of_all_flows'].max():.1%}",
    top3_th=", ".join(f"{FAMILY_TH[r.attack_family]} {r.share_of_all_flows:.1%}" for r in top3.itertuples()),
    small_th=", ".join(FAMILY_TH[f] for f in small["attack_family"]),
    quiet_en=" and ".join(quiet_days), quiet_th=" และ ".join(DAY_TH[d] for d in quiet_days),
    cross_list=", ".join(f"{v:.1%} of {k}" if 0 < v < 0.01 else f"{v:.0%} of {k}" for k, v in cross_order.items()),
    cross_list_th=", ".join(f"{v:.1%} ของ{FAMILY_TH[k]}" if 0 < v < 0.01 else f"{v:.0%} ของ{FAMILY_TH[k]}" for k, v in cross_order.items()),
    )


TEXT = {
    "en": dict(
        lang="en", title="Can a model catch a cyberattack it has never seen before?",
        subtitle="Four plain questions about detecting attacks in network traffic, answered with five days of labelled traffic from a research testbed (CIC-IDS2017).",
        kpi=[(N["total"], "network flows over five days"), (N["attack"], "of them are attacks"),
             (N["rand_recall"], "of attacks caught when the model has seen every attack type"),
             (N["cross_recall"], "caught when the attack types are new to the model")],
        how="How to read this chart", says="What the data says", means="What it means",
        note_title="Before you quote these numbers",
        note=["The traffic was generated in a <b>lab testbed in 2017</b>. Attacks were run on a schedule, so the share of attacks is far higher than on a real network.",
              "Friday's attack types do not occur on earlier days, so Q4 measures detection of unseen attack types, not the same attacks later in time.",
              "Published critiques report labelling errors in the original files; this project uses them as distributed."],
        sources=("Data: CIC-IDS2017, Sharafaldin, Lashkari and Ghorbani (2018), <a href=\"https://www.unb.ca/cic/datasets/ids-2017.html\">Canadian Institute for Cybersecurity</a>. "
                 "Method: <a href=\"METHODOLOGY.md\">METHODOLOGY</a>. Excel: <a href=\"results.xlsx\">results.xlsx</a>."),
        switch='<a href="th.html">ภาษาไทย</a>',
        glossary_title="The terms used on this page", glossary_tag="GLOSSARY",
        glossary=[("Flow", "One conversation between two computers, summarised as a single row: how long it lasted, how many packets, how much data."),
                  ("DoS / DDoS", "Flooding a server with requests so real users cannot reach it. DoS comes from one machine, DDoS from many at once."),
                  ("Port scan", "Knocking on every network 'door' of a machine to find which ones are open."),
                  ("Brute force", "Guessing passwords by trying many of them, here against FTP and SSH logins."),
                  ("Web attack", "Attacking a website's login or input forms (password guessing, cross-site scripting, SQL injection)."),
                  ("Botnet", "An infected computer quietly taking orders from an attacker."),
                  ("Infiltration", "An attacker already inside the network, moving from one machine to others.")],
        q=[
            dict(tag="Q1", question="How much of the traffic is an attack, and which attack type is most common?",
                 answer="About one flow in {one_in} is an attack, mostly flooding and scanning.",
                 shows="Left: each bar is a kind of traffic, blue for normal and red for attacks. The scale is logarithmic so that rare attacks stay visible; read the labels for exact counts. Right: how many attack flows were recorded on each day, coloured by type.",
                 says="{benign} of flows are normal and {attack} are attacks. {top3} make up almost all of them. {small} are each under {small_max}. {quiet_en_sentence}Each day has its own attack types.",
                 means="The loud attacks dominate the count: flooding a server (DoS, DDoS) and probing for open doors (port scan) generate huge numbers of connections. The quiet ones, such as botnet traffic or infiltration, are a tiny share of traffic, which is exactly what makes them hard to notice. The attack share here was set by the lab's schedule and is far higher than on a real network."),
            dict(tag="Q2", question="What does attack traffic look like next to normal traffic?",
                 answer="Different attacks look nothing alike, and some look just like normal traffic.",
                 shows="Each row is a kind of traffic and each panel is one measurement. The box covers the middle half of flows, the line inside it is the typical (median) value, and the whiskers cover 90% of flows. Compare each attack row with the Benign row at the top. Scales are logarithmic.",
                 says="A typical normal connection lasts {dur_benign}. A typical port-scan flow lasts {dur_ps}, while DoS flows last {dur_dos}. Botnet boxes largely overlap the Benign boxes.",
                 means="There is no single signature of 'an attack'. A scan is a burst of tiny, instant connections; a DoS holds connections open for a long time; botnet traffic is built to blend in. A detector tuned to one of these patterns will not automatically recognise the others, which sets up Q4."),
            dict(tag="Q3", question="Can a model tell attacks from normal traffic?",
                 answer="Yes: it catches {rand_recall} of attacks when it has seen examples of every type.",
                 shows="Each bar is one way of testing the same model. The blue bar tests it on a random 30% of flows from all five days, so every attack type it meets in the test also appeared in its training data.",
                 says="The model catches {rand_recall} of attacks, and {rand_prec} of its alerts are real attacks. Its weakest common type is {weakest} at {weakest_rate}.",
                 means="This is the kind of score usually reported for intrusion-detection models, and it looks close to perfect. Q4 shows why it should not be taken at face value."),
            dict(tag="Q4", question="Can it catch attack types it has never seen before?",
                 answer="Mostly no: it catches {cross_recall}.",
                 shows="Each attack type has two bars. Blue: the share caught in the random-split test from Q3. Red: the share caught when the model is trained on Monday to Thursday and tested on Friday, whose attack types never occur earlier in the week. 'Not in this test' means that attack type did not occur on Friday.",
                 says="On Friday the model catches {cross_list}. Overall that is {cross_recall} of attacks, down from {rand_recall}. When it does raise an alert it is still right {cross_prec} of the time; it simply stays silent on what it has not seen.",
                 means="The model learned to recognise the specific attacks it was shown, not attacks in general. A near-perfect test score says little about tomorrow's attack. Defences built on this kind of model need retraining on new attack types and a second layer that flags unusual behaviour."),
        ],
        labels=dict(share_x="Number of flows (log scale: each step is 10 times larger)", benign="Benign",
                    day_y="Attack flows", share_title="Q1. How much of the traffic is an attack, and which type?",
                    day_title="Q1. Which attacks happened on which day?", box_title="Q2. What does attack traffic look like next to normal traffic? (log scale)",
                    feat={"Flow Duration": "Duration (microseconds)", "Total Fwd Packets": "Packets sent",
                          "Flow Bytes/s": "Bytes per second", "Packet Length Mean": "Packet size (bytes)"},
                    rec_x="Share of that attack type caught", random_name="Attack types the model has seen (random split)",
                    cross_name="Attack types new to the model (Friday)", not_test="not in this test",
                    flows_caught="of {n} test flows caught", fam=lambda f: f),
    ),
    "th": dict(
        lang="th", title="โมเดลจับการโจมตีเครือข่ายที่ไม่เคยเห็นมาก่อนได้หรือไม่?",
        subtitle="ตอบสี่คำถามง่าย ๆ เรื่องการตรวจจับการโจมตีในทราฟฟิกเครือข่าย จากข้อมูลห้าวันที่มีป้ายกำกับจากห้องทดลอง (CIC-IDS2017)",
        kpi=[(N["total"], "flow ของเครือข่ายในห้าวัน"), (N["attack"], "เป็นการโจมตี"),
             (N["rand_recall"], "ของการโจมตีที่จับได้ เมื่อโมเดลเคยเห็นทุกประเภท"),
             (N["cross_recall"], "จับได้ เมื่อประเภทการโจมตีเป็นของใหม่สำหรับโมเดล")],
        how="วิธีอ่านกราฟนี้", says="ข้อมูลบอกอะไร", means="ความหมายคืออะไร",
        note_title="ก่อนนำตัวเลขไปใช้",
        note=["ทราฟฟิกถูกสร้างใน<b>ห้องทดลองปี 2017</b> โดยมีการโจมตีตามตารางที่กำหนด สัดส่วนการโจมตีจึงสูงกว่าเครือข่ายจริงมาก",
              "การโจมตีของวันศุกร์ไม่เกิดในวันก่อนหน้า คำถามที่ 4 จึงวัดการตรวจจับประเภทการโจมตีที่ไม่เคยเห็น ไม่ใช่การโจมตีเดิมในช่วงหลัง",
              "มีการวิจารณ์ที่พบข้อผิดพลาดของป้ายกำกับในไฟล์ต้นฉบับ โครงการนี้ใช้ไฟล์ตามที่แจกจ่ายมา"],
        sources=("ข้อมูล: CIC-IDS2017, Sharafaldin, Lashkari และ Ghorbani (2018) จาก <a href=\"https://www.unb.ca/cic/datasets/ids-2017.html\">Canadian Institute for Cybersecurity</a> "
                 "วิธีการ: <a href=\"METHODOLOGY_TH.docx\">คำอธิบายวิธีการ (Word)</a> ไฟล์ Excel: <a href=\"results.xlsx\">results.xlsx</a>"),
        switch='<a href="index.html">English</a>',
        glossary_title="คำศัพท์ที่ใช้ในหน้านี้", glossary_tag="คำศัพท์",
        glossary=[("Flow", "การสนทนาหนึ่งครั้งระหว่างคอมพิวเตอร์สองเครื่อง สรุปเป็นหนึ่งแถว: ใช้เวลานานแค่ไหน ส่งกี่แพ็กเก็ต และข้อมูลกี่ไบต์"),
                  ("DoS / DDoS", "ท่วมเซิร์ฟเวอร์ด้วยคำขอจนผู้ใช้จริงเข้าไม่ได้ DoS มาจากเครื่องเดียว DDoS มาจากหลายเครื่องพร้อมกัน"),
                  ("Port scan", "เคาะทุกช่องประตูของเครื่องเพื่อดูว่าช่องไหนเปิดอยู่"),
                  ("Brute force", "เดารหัสผ่านโดยลองทีละหลาย ๆ ค่า ในที่นี้คือการล็อกอิน FTP และ SSH"),
                  ("Web attack", "โจมตีหน้าล็อกอินหรือฟอร์มกรอกข้อมูลของเว็บไซต์ (เช่น เดารหัส, XSS, SQL injection)"),
                  ("Botnet", "คอมพิวเตอร์ที่ติดมัลแวร์และรับคำสั่งจากผู้โจมตีโดยที่เจ้าของไม่รู้"),
                  ("Infiltration", "ผู้โจมตีที่เข้ามาอยู่ในเครือข่ายแล้ว และเคลื่อนไปยังเครื่องอื่น")],
        q=[
            dict(tag="คำถามที่ 1", question="การโจมตีคิดเป็นเท่าไรของทราฟฟิก และประเภทไหนพบบ่อยที่สุด?",
                 answer="ประมาณ 1 ใน {one_in} ของ flow เป็นการโจมตี ส่วนใหญ่เป็นการท่วมและการสแกน",
                 shows="ด้านซ้าย: แต่ละแท่งคือทราฟฟิกประเภทหนึ่ง สีน้ำเงินคือปกติ สีแดงคือการโจมตี สเกลเป็นลอการิทึมเพื่อให้การโจมตีที่พบน้อยยังเห็นได้ อ่านตัวเลขจากป้าย ด้านขวา: จำนวน flow ที่เป็นการโจมตีในแต่ละวัน แยกตามประเภท",
                 says="{benign} ของ flow เป็นปกติ และ {attack} เป็นการโจมตี {top3_th} คิดเป็นเกือบทั้งหมด แต่ละประเภท {small_th} มีน้อยกว่า {small_max} {quiet_th_sentence}แต่ละวันมีประเภทการโจมตีของตัวเอง",
                 means="การโจมตีที่เห็นชัดกินสัดส่วนการนับ: การท่วมเซิร์ฟเวอร์ (DoS, DDoS) และการสำรวจหาประตูที่เปิด (port scan) สร้างการเชื่อมต่อจำนวนมหาศาล ส่วนประเภทที่เงียบ เช่น บอตเน็ตหรือการซึมเข้าภายใน มีสัดส่วนเล็กมาก ซึ่งทำให้ตรวจพบได้ยาก สัดส่วนการโจมตีนี้กำหนดโดยตารางของห้องทดลอง สูงกว่าเครือข่ายจริงมาก"),
            dict(tag="คำถามที่ 2", question="ทราฟฟิกการโจมตีต่างจากทราฟฟิกปกติอย่างไร?",
                 answer="การโจมตีแต่ละประเภทหน้าตาต่างกันมาก และบางประเภทดูเหมือนทราฟฟิกปกติ",
                 shows="แต่ละแถวคือทราฟฟิกประเภทหนึ่ง แต่ละช่องคือการวัดหนึ่งค่า กล่องครอบคลุม flow ครึ่งกลาง เส้นในกล่องคือค่าทั่วไป (มัธยฐาน) และเส้นปลายครอบคลุม flow 90% เทียบแถวการโจมตีแต่ละแถวกับแถวปกติด้านบน สเกลเป็นลอการิทึม",
                 says="การเชื่อมต่อปกติทั่วไปใช้เวลา {dur_benign} flow การสแกนพอร์ตทั่วไปใช้เวลา {dur_ps} ส่วน DoS ใช้เวลา {dur_dos} กล่องของบอตเน็ตทับซ้อนกับกล่องปกติเป็นส่วนใหญ่",
                 means="ไม่มีลายเซ็นเดียวที่บอกว่า 'นี่คือการโจมตี' การสแกนคือชุดการเชื่อมต่อเล็ก ๆ ที่เกิดทันที DoS ทำให้การเชื่อมต่อค้างไว้นาน และบอตเน็ตถูกออกแบบให้กลมกลืน ตัวตรวจจับที่ปรับไว้กับรูปแบบหนึ่งจะไม่รู้จักอีกรูปแบบโดยอัตโนมัติ ซึ่งนำไปสู่คำถามที่ 4"),
            dict(tag="คำถามที่ 3", question="โมเดลแยกการโจมตีออกจากทราฟฟิกปกติได้หรือไม่?",
                 answer="ได้: จับการโจมตีได้ {rand_recall} เมื่อเคยเห็นตัวอย่างทุกประเภท",
                 shows="แต่ละแท่งคือการทดสอบโมเดลเดียวกันในรูปแบบหนึ่ง แท่งสีน้ำเงินทดสอบด้วย flow 30% ที่สุ่มจากทั้งห้าวัน การโจมตีทุกประเภทที่โมเดลเจอในการทดสอบจึงเคยปรากฏในข้อมูลฝึกด้วย",
                 says="โมเดลจับการโจมตีได้ {rand_recall} และ {rand_prec} ของการแจ้งเตือนเป็นการโจมตีจริง ประเภทที่จับได้น้อยที่สุดคือ {weakest} ที่ {weakest_rate}",
                 means="นี่คือคะแนนแบบที่มักรายงานสำหรับโมเดลตรวจจับการบุกรุก และดูเกือบสมบูรณ์ คำถามที่ 4 แสดงว่าไม่ควรเชื่อคะแนนนี้โดยไม่ตรวจสอบเพิ่ม"),
            dict(tag="คำถามที่ 4", question="โมเดลจับการโจมตีประเภทที่ไม่เคยเห็นได้หรือไม่?",
                 answer="ส่วนใหญ่ไม่ได้: จับได้ {cross_recall}",
                 shows="แต่ละประเภทการโจมตีมีสองแท่ง สีน้ำเงิน: สัดส่วนที่จับได้ในการทดสอบแบบสุ่มจากคำถามที่ 3 สีแดง: สัดส่วนที่จับได้เมื่อฝึกด้วยวันจันทร์ถึงพฤหัสบดี แล้วทดสอบด้วยวันศุกร์ ซึ่งประเภทการโจมตีไม่เกิดในช่วงก่อนหน้า 'ไม่มีในการทดสอบนี้' หมายถึงประเภทนั้นไม่เกิดในวันศุกร์",
                 says="วันศุกร์โมเดลจับได้ {cross_list_th} โดยรวมคือ {cross_recall} ของการโจมตี ลดลงจาก {rand_recall} เมื่อโมเดลแจ้งเตือน ก็ยังถูกต้อง {cross_prec} ของเวลา เพียงแต่ไม่แจ้งเตือนสิ่งที่ไม่เคยเห็น",
                 means="โมเดลเรียนรู้จะจำการโจมตีเฉพาะที่เคยถูกแสดงให้ดู ไม่ใช่การโจมตีโดยทั่วไป คะแนนทดสอบที่เกือบสมบูรณ์บอกได้น้อยมากเกี่ยวกับการโจมตีของพรุ่งนี้ การป้องกันที่ใช้โมเดลแบบนี้ต้องฝึกใหม่เมื่อมีการโจมตีประเภทใหม่ และควรมีชั้นที่สองที่ตรวจพฤติกรรมผิดปกติ"),
        ],
        labels=dict(share_x="จำนวน flow (สเกลลอการิทึม: แต่ละขั้นใหญ่กว่า 10 เท่า)", benign="ปกติ",
                    day_y="flow ที่เป็นการโจมตี", share_title="คำถามที่ 1: การโจมตีคิดเป็นเท่าไร และเป็นประเภทไหน?",
                    day_title="คำถามที่ 1: การโจมตีแต่ละประเภทเกิดวันไหน?", box_title="คำถามที่ 2: ทราฟฟิกการโจมตีต่างจากปกติอย่างไร? (สเกลลอการิทึม)",
                    feat={"Flow Duration": "ระยะเวลา (ไมโครวินาที)", "Total Fwd Packets": "จำนวนแพ็กเก็ตที่ส่ง",
                          "Flow Bytes/s": "ไบต์ต่อวินาที", "Packet Length Mean": "ขนาดแพ็กเก็ต (ไบต์)"},
                    rec_x="สัดส่วนของการโจมตีประเภทนั้นที่จับได้", random_name="การโจมตีที่โมเดลเคยเห็น (สุ่มทดสอบ)",
                    cross_name="การโจมตีที่เป็นของใหม่สำหรับโมเดล (วันศุกร์)", not_test="ไม่มีในการทดสอบนี้",
                    flows_caught="จับได้จาก flow ทดสอบ {n} รายการ", fam=lambda f: FAMILY_TH.get(f, f)),
    ),
}

# Sentences that depend on whether there are quiet days, in each language.
N["quiet_en_sentence"] = (f"{N['quiet_en']} had no attacks. " if quiet_days else "")
N["quiet_th_sentence"] = (f"{N['quiet_th']} ไม่มีการโจมตีเลย " if quiet_days else "")


def layout(fig, height=380, **kw):
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=60, b=10), template="plotly_white",
        font=dict(family="system-ui, -apple-system, Segoe UI, Sans Thai, sans-serif", size=13),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0), **kw,
    )
    fig.update_yaxes(automargin=True, ticksuffix="  ")
    return fig.to_html(full_html=False, include_plotlyjs=False, config={"displayModeBar": False, "responsive": True})


def charts(L):
    b = L["labels"]
    fam = b["fam"]
    names = [fam(f) for f in share["attack_family"]]
    fig = go.Figure(go.Bar(
        x=share["flows"], y=names, orientation="h",
        marker_color=[BLUE if f == "Benign" else RED for f in share["attack_family"]],
        text=[f"{n:,} ({s:.1%})" for n, s in zip(share["flows"], share["share_of_all_flows"])],
        textposition="outside", cliponaxis=False,
    ))
    fig.update_xaxes(type="log", title=b["share_x"], range=[0, len(str(int(share["flows"].max()))) + 1.2])
    q1a = layout(fig, 380)

    fig = go.Figure()
    for f in attacks["attack_family"]:
        if f in pivot.columns:
            fig.add_bar(x=pivot.index, y=pivot[f], name=fam(f), marker_color=FAMILY_COLORS.get(f, GREY))
    fig.update_yaxes(title=b["day_y"])
    q1b = layout(fig, 380, barmode="stack")

    features = {k: v for k, v in b["feat"].items() if k in sample.columns}
    order = [f for f in ["Benign"] + attacks["attack_family"].tolist() if f in set(sample["attack_family"])][::-1]
    n_rows = (len(features) + 1) // 2
    fig = make_subplots(rows=n_rows, cols=2, shared_yaxes=True, horizontal_spacing=0.04, vertical_spacing=0.12,
                        subplot_titles=list(features.values()))
    for i, feat in enumerate(features):
        q = (sample.assign(v=sample[feat].abs() + 1).groupby("attack_family")["v"]
             .quantile([0.05, 0.25, 0.5, 0.75, 0.95]).unstack().reindex(order))
        fig.add_trace(go.Box(
            y=[fam(f) for f in order], q1=q[0.25], median=q[0.5], q3=q[0.75], lowerfence=q[0.05], upperfence=q[0.95],
            orientation="h", showlegend=False, marker_color=RED, line_width=1.5,
        ), row=i // 2 + 1, col=i % 2 + 1)
        fig.update_xaxes(type="log", row=i // 2 + 1, col=i % 2 + 1)
    q2 = layout(fig, 360 * n_rows)

    fig = go.Figure(go.Bar(
        x=[metrics.loc[e, "recall"] for e in ([RANDOM, CROSS] if has_cross else [RANDOM])],
        y=[b["random_name"], b["cross_name"]][: 2 if has_cross else 1], orientation="h",
        marker_color=[BLUE, RED][: 2 if has_cross else 1],
        text=[f"{metrics.loc[e, 'recall']:.1%}" for e in ([RANDOM, CROSS] if has_cross else [RANDOM])],
        textposition="outside", cliponaxis=False,
    ))
    fig.update_xaxes(tickformat=".0%", range=[0, 1.12], title=b["rec_x"])
    fig.update_yaxes(autorange="reversed")
    q3 = layout(fig, 230)

    fam_order = [f for f in attacks["attack_family"] if f in rec.index][::-1]
    fig = go.Figure()
    evals = [RANDOM] + ([CROSS] if has_cross else [])
    for e, color, name in zip(evals, (BLUE, RED), (b["random_name"], b["cross_name"])):
        vals = rec[e].reindex(fam_order)
        fig.add_bar(
            y=[fam(f) for f in fam_order], x=vals.fillna(0), orientation="h", name=name, marker_color=color,
            text=[pct(v) if pd.notna(v) else b["not_test"] for v in vals], textposition="outside", cliponaxis=False,
        )
    fig.update_xaxes(tickformat=".0%", range=[0, 1.2], title=b["rec_x"])
    q4 = layout(fig, 520, barmode="group")
    return {"Q1": [q1a, q1b], "Q2": [q2], "Q3": [q3], "Q4": [q4]}


def page(L):
    ch = charts(L)
    sections = "".join(
        f"""
<section id="q{q['tag'][-1]}">
  <p class="tag">{q['tag']}</p>
  <h2>{q['question']}</h2>
  <p class="answer">{q['answer'].format(**N)}</p>
  <div class="charts {'two' if len(ch['Q' + q['tag'][-1]]) > 1 else 'one'}">{''.join(f'<div class="chart">{c}</div>' for c in ch['Q' + q['tag'][-1]])}</div>
  <dl>
    <dt>{L['how']}</dt><dd>{q['shows']}</dd>
    <dt>{L['says']}</dt><dd>{q['says'].format(**N)}</dd>
    <dt>{L['means']}</dt><dd>{q['means'].format(**N)}</dd>
  </dl>
</section>""" for q in L["q"])
    kpis = "".join(f'<div class="kpi"><b>{v}</b><span>{l}</span></div>' for v, l in L["kpi"])
    nav = "".join(f'<a href="#q{q["tag"][-1]}">Q{q["tag"][-1]}</a>' for q in L["q"])
    glossary = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in L["glossary"])
    notes = "".join(f"<li>{n}</li>" for n in L["note"])
    font = "'Sarabun', 'Leelawadee UI', 'Tahoma', system-ui, sans-serif" if L["lang"] == "th" else "system-ui, -apple-system, 'Segoe UI', sans-serif"
    return f"""<!DOCTYPE html>
<html lang="{L['lang']}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{L['title']}</title>
<script src="https://cdn.plot.ly/plotly-{get_plotlyjs_version()}.min.js" charset="utf-8"></script>
<style>
  body {{ margin: 0; background: #f4f5f7; color: #1d2733; font: 16px/1.7 {font}; }}
  header {{ background: #14213d; color: #fff; padding: 40px 20px 28px; }}
  header h1 {{ margin: 0 0 8px; font-size: 30px; line-height: 1.3; }}
  header p {{ margin: 0; color: #c9d1dc; max-width: 760px; }}
  .wrap {{ max-width: 1040px; margin: 0 auto; padding: 0 20px; }}
  nav {{ margin-top: 18px; }}
  nav a, .switch {{ color: #fff; border: 1px solid #5b6a85; border-radius: 16px; padding: 3px 14px; margin-right: 8px; text-decoration: none; font-size: 14px; }}
  .switch {{ float: right; margin-right: 0; }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin: 24px 0; }}
  .kpi, section, .note {{ background: #fff; border-radius: 10px; box-shadow: 0 1px 3px rgba(20, 33, 61, .12); }}
  .kpi {{ padding: 16px 18px; }}
  .kpi b {{ display: block; font-size: 26px; }}
  .kpi span {{ color: #5a6675; font-size: 14px; }}
  section {{ padding: 24px 26px; margin-bottom: 24px; }}
  .tag {{ margin: 0; color: {RED}; font-weight: 700; }}
  h2 {{ margin: 2px 0 6px; font-size: 23px; line-height: 1.3; }}
  .answer {{ margin: 0 0 12px; font-size: 18px; font-weight: 600; color: #14213d; }}
  .charts.two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  .chart {{ min-width: 0; }}
  dl {{ margin: 14px 0 0; border-top: 1px solid #e3e6ea; padding-top: 12px; }}
  dt {{ font-weight: 700; font-size: 14px; color: #5a6675; margin-top: 10px; }}
  dd {{ margin: 2px 0 0; }}
  .note {{ padding: 20px 26px; margin-bottom: 40px; border-left: 5px solid #e9a100; }}
  .note h2 {{ font-size: 19px; }}
  .note li {{ margin-bottom: 4px; }}
  @media (max-width: 760px) {{ .charts.two {{ grid-template-columns: 1fr; }} header h1 {{ font-size: 24px; }} }}
</style>
</head>
<body>
<header><div class="wrap">
  {L['switch']}
  <h1>{L['title']}</h1>
  <p>{L['subtitle']}</p>
  <nav>{nav}</nav>
</div></header>
<div class="wrap">
  <div class="kpis">{kpis}</div>
  {sections}
  <section id="glossary">
    <p class="tag">{L['glossary_tag']}</p>
    <h2>{L['glossary_title']}</h2>
    <dl>{glossary}</dl>
  </section>
  <div class="note">
    <h2>{L['note_title']}</h2>
    <ul>{notes}</ul>
    <p>{L['sources']}</p>
  </div>
</div>
</body>
</html>
"""


Path("docs").mkdir(exist_ok=True)
Path("docs/index.html").write_text(page(TEXT["en"]), encoding="utf-8")
Path("docs/th.html").write_text(page(TEXT["th"]), encoding="utf-8")
for name in ("results.xlsx", "METHODOLOGY_TH.docx"):
    src = Path("output") / name
    if src.exists():
        shutil.copy2(src, Path("docs") / name)
print("wrote docs/index.html and docs/th.html")
