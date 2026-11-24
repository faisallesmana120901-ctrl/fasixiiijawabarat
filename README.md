# Portal FASI XIII Sumedang — Frontend + Backend

Portal asli dipertahankan, tetapi autentikasi dan penyimpanan dipindahkan ke server.

## Fitur keamanan
- Admin diverifikasi di backend menggunakan bcrypt (hash password).
- Session server-side disimpan di SQLite; cookie HttpOnly + SameSite Strict.
- Semua endpoint tulis/baca dashboard admin membutuhkan sesi yang valid.
- Batas percobaan login: 8 kali per 15 menit per IP.
- Database SQLite persisten di `data/fasi.sqlite`.
- Kredensial admin tidak dikirim ke browser dan tidak disimpan di data portal.

## Menjalankan di komputer lokal
1. Instal Node.js 20 atau lebih baru.
2. Salin `.env.example` menjadi `.env`.
3. Ubah `SESSION_SECRET`, `ADMIN_USERNAME`, dan `ADMIN_PASSWORD`.
   Password admin minimal 12 karakter. Jangan gunakan password contoh.
4. Jalankan:
   ```bash
   npm install
   npm start
   ```
5. Buka `http://localhost:3000`.

## Menayangkan agar bisa diakses publik
Deploy folder proyek ke VPS/server yang mendukung Node.js. Gunakan domain + HTTPS (Nginx/Caddy reverse proxy atau platform hosting Node). Atur `NODE_ENV=production`, `TRUST_PROXY=1` bila memakai reverse proxy, serta environment variables yang kuat. Pastikan folder `data/` berada di persistent disk dan dicadangkan secara berkala. Jangan menaruh `.env`, database, atau file server di folder `public`.

## Mengubah akun admin
Masuk Dashboard Admin → Pengaturan Web, Logo & Akun → Ubah Akun Login Khusus Admin. Password baru minimal 10 karakter pada form UI; backend menerapkan minimal 12 karakter. Gunakan 12 karakter atau lebih.

## Catatan penting
- Website ini tidak lagi aman jika dibuka dengan cara klik file HTML langsung (`file://`). Jalankan melalui server.
- File `data/initial-state.json` adalah data awal yang disalin ke database saat pertama kali server dijalankan. Setelah database terbentuk, perubahan disimpan di `data/fasi.sqlite`.
- Untuk backup, gunakan fitur backup JSON di dashboard dan backup file SQLite di server.
- Pasang HTTPS sebelum digunakan melalui internet. Jangan mengandalkan login frontend atau menyembunyikan tombol admin sebagai pengamanan; proteksi sesungguhnya berada pada endpoint backend.
