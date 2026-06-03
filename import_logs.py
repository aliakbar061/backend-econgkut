import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
import dateutil.parser
import uuid

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb+srv://aliakbar:T2gOidZ5N5U1Xn0B@cluster0.vxy4f.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
client = AsyncIOMotorClient(MONGODB_URL)
db = client.econgkut

csv_data = """id,user_id,user_name,action,details,created_at
act-001,100583532387678793779,Ali Akbar,LOGIN,Berhasil login ke sistem,2025-11-10T08:00:00.000000
act-002,200583532387678793780,Yulianti,LOGIN,Berhasil login ke sistem,2025-11-10T08:05:00.000000
act-003,300583532387678793781,Eka Wahyuni,LOGIN,Berhasil login ke sistem,2025-11-10T08:10:00.000000
act-004,400583532387678793782,Syahru Ramadhan Saharuddin,LOGIN,Berhasil login ke sistem,2025-11-11T07:55:00.000000
act-005,500583532387678793783,Budi Santoso,CREATE_BOOKING,Membuat pesanan baru untuk Sampah Organik (estimasi 30 kg) dengan ID PES-001,2025-11-11T09:00:00.000000
act-006,100583532387678793779,Ali Akbar,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-001 menjadi confirmed,2025-11-11T09:15:00.000000
act-007,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-001 menjadi in-transit,2025-11-11T13:00:00.000000
act-008,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-001 menjadi completed,2025-11-11T14:30:00.000000
act-009,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Membuat pesanan baru untuk Plastik dan Kertas (estimasi 15 kg) dengan ID PES-002,2025-11-12T10:00:00.000000
act-010,200583532387678793780,Yulianti,EXPORT_REPORT,Mengekspor laporan absensi bulan Oktober 2025 ke Excel,2025-11-12T11:00:00.000000
act-011,800583532387678793786,Yasinta Weka,LOGIN,Berhasil login ke sistem,2025-11-13T08:20:00.000000
act-012,800583532387678793786,Yasinta Weka,CREATE_EXPENSE,Menambahkan pengeluaran operasional: Pembelian solar Rp 500.000,2025-11-13T09:00:00.000000
act-013,900583532387678793787,Syahiq Arminanda,LOGIN,Berhasil login ke sistem,2025-11-14T08:00:00.000000
act-014,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup database harian ke Google Drive - sukses,2025-11-15T15:00:00.000000
act-015,200583532387678793780,Yulianti,REPORT_ISSUE,Melaporkan kendala: Data karyawan tidak bisa diubah,2025-11-16T09:30:00.000000
act-016,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Mengubah status kendala ISSUE-001 menjadi Resolved,2025-11-16T10:15:00.000000
act-017,400583532387678793782,Syahru Ramadhan Saharuddin,CREATE_BOOKING,Pemesanan untuk pelanggan tetap: Bapak RT RW (Sampah Campuran 50 kg) ID PES-003,2025-11-17T08:30:00.000000
act-018,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-003 menjadi in-transit,2025-11-17T09:45:00.000000
act-019,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-003 menjadi completed,2025-11-17T11:20:00.000000
act-020,300583532387678793781,Eka Wahyuni,VIEW_DASHBOARD,Melihat dashboard ringkasan pendapatan dan kinerja divisi,2025-11-20T09:00:00.000000
act-021,100583532387678793779,Ali Akbar,CHECK_SYSTEM,Melakukan pengecekan rutin server - semua normal,2025-12-01T08:00:00.000000
act-022,200583532387678793780,Yulianti,MANAGE_USER,Menambahkan user baru: Andi Saputra sebagai staff IT,2025-12-02T10:30:00.000000
act-023,800583532387678793786,Yasinta Weka,CREATE_REVENUE,Menambahkan pendapatan dari pelanggan Budi Santoso Rp 150.000,2025-12-03T14:00:00.000000
act-024,900583532387678793787,Syahiq Arminanda,VERIFY_PAYMENT,Memverifikasi pembayaran dari Dewi Kartika,2025-12-04T11:00:00.000000
act-025,400583532387678793782,Syahru Ramadhan Saharuddin,EXPORT_REPORT,Mengekspor laporan operasional bulan November 2025,2025-12-05T09:30:00.000000
act-026,600583532387678793784,Siti Rahima Rahim,INPUT_WEIGHT,Menginput berat sampah pesanan PES-002: 16.5 kg,2025-12-06T08:00:00.000000
act-027,100583532387678793779,Ali Akbar,UPDATE_RBAC,Menambahkan akses untuk divisi baru: Marketing,2025-12-10T13:00:00.000000
act-028,300583532387678793781,Eka Wahyuni,APPROVE_BUDGET,Menyetujui anggaran pembelian alat pengolahan sampah Rp 5.000.000,2025-12-15T10:00:00.000000
act-029,200583532387678793780,Yulianti,REPORT_ISSUE,Melaporkan kendala: Fitur absensi tidak sinkron,2026-01-05T08:45:00.000000
act-030,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Mengubah status kendala ISSUE-002 menjadi In Progress,2026-01-05T09:20:00.000000
act-031,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Mengubah status kendala ISSUE-002 menjadi Resolved - perbaikan sinkronisasi,2026-01-06T11:00:00.000000
act-032,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Membuat pesanan baru untuk Kardus (estimasi 20 kg) ID PES-004,2026-01-10T09:00:00.000000
act-033,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-004 menjadi confirmed,2026-01-10T09:30:00.000000
act-034,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-004 menjadi in-transit,2026-01-10T13:15:00.000000
act-035,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-004 menjadi completed,2026-01-10T15:00:00.000000
act-036,800583532387678793786,Yasinta Weka,EXPORT_FINANCE,Mengekspor laporan keuangan Desember 2025,2026-01-15T10:00:00.000000
act-037,900583532387678793787,Syahiq Arminanda,INPUT_EXPENSE,Input biaya perawatan kendaraan Rp 750.000,2026-01-20T11:30:00.000000
act-038,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup mingguan ke harddisk eksternal - sukses,2026-01-22T16:00:00.000000
act-039,500583532387678793783,Budi Santoso,LOGIN,Berhasil login,2026-02-01T07:00:00.000000
act-040,500583532387678793783,Budi Santoso,CREATE_BOOKING,Pesanan rutin sampah organik 35 kg ID PES-005,2026-02-01T07:15:00.000000
act-041,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-005,2026-02-01T08:00:00.000000
act-042,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-005,2026-02-01T09:30:00.000000
act-043,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-005 - berat 34 kg,2026-02-01T11:00:00.000000
act-044,200583532387678793780,Yulianti,EXPORT_REPORT,Ekspor rekap kehadiran Januari 2026,2026-02-05T09:00:00.000000
act-045,300583532387678793781,Eka Wahyuni,VIEW_REPORT,Melihat laporan laba rugi Januari 2026,2026-02-10T14:00:00.000000
act-046,100583532387678793779,Ali Akbar,CHECK_SERVER,Pengecekan server - response time 1.2 detik,2026-02-15T08:00:00.000000
act-047,800583532387678793786,Yasinta Weka,CREATE_REVENUE,Menambahkan pemasukan dari pelanggan Dewi Kartika Rp 200.000,2026-03-01T09:00:00.000000
act-048,900583532387678793787,Syahiq Arminanda,VERIFY_PAYMENT,Memverifikasi pembayaran dari Bapak RT RW,2026-03-02T10:00:00.000000
act-049,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Pesanan plastik dan kaca ID PES-006,2026-03-05T11:00:00.000000
act-050,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-006,2026-03-05T11:30:00.000000
act-051,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-006,2026-03-05T13:00:00.000000
act-052,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-006 - berat 22 kg,2026-03-05T15:30:00.000000
act-053,200583532387678793780,Yulianti,REPORT_ISSUE,Kendala: Laporan evaluasi kinerja tidak muncul,2026-03-10T08:30:00.000000
act-054,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Resolved ISSUE-003 - query error diperbaiki,2026-03-10T10:00:00.000000
act-055,300583532387678793781,Eka Wahyuni,APPROVE_RECRUITMENT,Menyetujui rekrutmen 2 orang karyawan lapangan,2026-03-15T13:00:00.000000
act-056,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup database penuh ke Google Drive,2026-03-25T15:00:00.000000
act-057,800583532387678793786,Yasinta Weka,EXPORT_FINANCE,Ekspor laporan keuangan Maret 2026,2026-04-01T09:00:00.000000
act-058,900583532387678793787,Syahiq Arminanda,INPUT_EXPENSE,Biaya perbaikan mesin pengolahan Rp 1.200.000,2026-04-05T10:30:00.000000
act-059,400583532387678793782,Syahru Ramadhan Saharuddin,CREATE_BOOKING,Pesanan dari pelanggan baru: Toko Makmur (sampah kardus 100 kg) ID PES-007,2026-04-10T08:00:00.000000
act-060,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Confirmed PES-007,2026-04-10T08:30:00.000000
act-061,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-007,2026-04-10T10:00:00.000000
act-062,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-007 - berat 105 kg,2026-04-10T14:00:00.000000
act-063,200583532387678793780,Yulianti,MANAGE_USER,Menonaktifkan akun karyawan yang berhenti: Andi Saputra,2026-04-15T11:00:00.000000
act-064,100583532387678793779,Ali Akbar,UPDATE_RBAC,Menyesuaikan hak akses untuk divisi Keuangan,2026-04-20T09:00:00.000000
act-065,300583532387678793781,Eka Wahyuni,VIEW_DASHBOARD,Melihat dashboard bulan April - pendapatan naik 15%,2026-04-25T08:00:00.000000
act-066,500583532387678793783,Budi Santoso,CREATE_BOOKING,Pesanan rutin 40 kg sampah campuran ID PES-008,2026-05-02T07:00:00.000000
act-067,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-008,2026-05-02T07:45:00.000000
act-068,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-008,2026-05-02T09:00:00.000000
act-069,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-008 - berat 42 kg,2026-05-02T11:30:00.000000
act-070,800583532387678793786,Yasinta Weka,CREATE_REVENUE,Pendapatan dari pesanan PES-008 Rp 210.000,2026-05-02T13:00:00.000000
act-071,200583532387678793780,Yulianti,EXPORT_REPORT,Ekspor rekap evaluasi kinerja April 2026,2026-05-05T09:00:00.000000
act-072,100583532387678793779,Ali Akbar,CHECK_SYSTEM,Pengecekan sistem - semua berjalan normal,2026-05-10T08:00:00.000000
act-073,700583532387678793785,Dewi Kartika,LOGIN,Berhasil login,2026-05-12T10:00:00.000000
act-074,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Pesanan plastik dan kertas ID PES-009,2026-05-12T10:15:00.000000
act-075,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-009,2026-05-12T10:45:00.000000
act-076,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-009,2026-05-12T13:00:00.000000
act-077,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-009 - berat 18 kg,2026-05-12T15:00:00.000000
act-078,900583532387678793787,Syahiq Arminanda,VERIFY_PAYMENT,Verifikasi pembayaran dari Toko Makmur,2026-05-15T11:00:00.000000
act-079,300583532387678793781,Eka Wahyuni,APPROVE_BUDGET,Menyetujui anggaran pengembangan aplikasi ECOngkut,2026-05-20T14:00:00.000000
act-080,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup full + restore test - sukses,2026-05-27T16:00:00.000000
act-081,600583532387678793784,Siti Rahima Rahim,INPUT_WEIGHT,Input berat sampah pesanan PES-010 (belum tercatat),2026-06-01T08:00:00.000000
act-082,400583532387678793782,Syahru Ramadhan Saharuddin,CREATE_BOOKING,Pesanan dari pelanggan "Kenektik 1" untuk Kaca 10 kg ID PES-010,2026-06-02T08:30:00.000000
act-083,100583532387678793779,Ali Akbar,UPDATE_BOOKING_STATUS,Confirmed PES-010,2026-06-02T09:00:00.000000
act-084,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-010,2026-06-02T10:00:00.000000
act-085,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-010,2026-06-02T11:00:00.000000
act-086,200583532387678793780,Yulianti,REPORT_ISSUE,Melaporkan kendala: Export data karyawan lambat,2026-06-02T13:00:00.000000
act-087,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Resolved ISSUE-004 - optimized query,2026-06-02T13:30:00.000000
act-088,300583532387678793781,Eka Wahyuni,VIEW_REPORT,Melihat laporan kinerja bulan Mei,2026-06-02T14:00:00.000000
"""

async def run():
    lines = csv_data.strip().split('\\n')[1:]
    
    logs = []
    issues = {} # Map to generate system issues

    for line in lines:
        if not line.strip(): continue
        parts = line.split(',')
        if len(parts) >= 6:
            # Reconstruct details in case of commas
            act_id = parts[0]
            user_id = parts[1]
            user_name = parts[2]
            action = parts[3]
            created_at_str = parts[-1]
            details = ','.join(parts[4:-1])
            
            created_at = dateutil.parser.isoparse(created_at_str).replace(tzinfo=timezone.utc)
            
            # Check if this log already exists by ID
            existing = await db.activity_logs.find_one({"id": act_id})
            if not existing:
                logs.append({
                    "id": act_id,
                    "user_id": user_id,
                    "user_name": user_name,
                    "action": action,
                    "details": details,
                    "created_at": created_at
                })

            # Process System Issues based on REPORT_ISSUE and UPDATE_ISSUE
            if action == 'REPORT_ISSUE':
                issue_num = ""
                # Map based on act_id known above
                if act_id == "act-015": issue_num = "ISSUE-001"
                elif act_id == "act-029": issue_num = "ISSUE-002"
                elif act_id == "act-053": issue_num = "ISSUE-003"
                elif act_id == "act-086": issue_num = "ISSUE-004"
                
                if issue_num:
                    issues[issue_num] = {
                        "id": issue_num,
                        "reporter_id": user_id,
                        "reporter_name": user_name,
                        "reporter_division": "Operasional", # Assuming default
                        "issue_type": "Lainnya",
                        "description": details,
                        "priority": "Sedang",
                        "contact_info": "",
                        "status": "Pending", # Will be overwritten if UPDATE_ISSUE occurs
                        "created_at": created_at,
                        "updated_at": created_at
                    }

            if action == 'UPDATE_ISSUE':
                if "ISSUE-001" in details and "ISSUE-001" in issues:
                    issues["ISSUE-001"]["status"] = "Resolved"
                    issues["ISSUE-001"]["updated_at"] = created_at
                if "ISSUE-002" in details and "ISSUE-002" in issues:
                    if "In Progress" in details:
                        issues["ISSUE-002"]["status"] = "In Progress"
                    if "Resolved" in details:
                        issues["ISSUE-002"]["status"] = "Resolved"
                    issues["ISSUE-002"]["updated_at"] = created_at
                if "ISSUE-003" in details and "ISSUE-003" in issues:
                    issues["ISSUE-003"]["status"] = "Resolved"
                    issues["ISSUE-003"]["updated_at"] = created_at
                if "ISSUE-004" in details and "ISSUE-004" in issues:
                    issues["ISSUE-004"]["status"] = "Resolved"
                    issues["ISSUE-004"]["updated_at"] = created_at

    if logs:
        await db.activity_logs.insert_many(logs)
        print(f"Inserted {len(logs)} activity logs.")
    else:
        print("No new activity logs to insert.")

    # Insert/Update issues
    for issue_id, issue_data in issues.items():
        existing_issue = await db.issues.find_one({"id": issue_id})
        if not existing_issue:
            await db.issues.insert_one(issue_data)
            print(f"Inserted system issue {issue_id}")
        else:
            await db.issues.update_one({"id": issue_id}, {"$set": {"status": issue_data["status"], "updated_at": issue_data["updated_at"]}})
            print(f"Updated system issue {issue_id}")

if __name__ == "__main__":
    asyncio.run(run())
