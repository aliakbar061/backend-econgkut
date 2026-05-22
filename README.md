# ECOngkut - Backend API

Platform pemesanan truk sampah yang mudah, cepat, dan ramah lingkungan. Sistem pengangkutan sampah organik dan non-organik yang dapat didaur ulang.

## 🌍 Latar Belakang

Backend ECOngkut lahir dari kepedulian terhadap kondisi pemulung sampah di kota-kota besar yang seringkali tidak memiliki pekerjaan lain dan tinggal di tempat yang tidak memadai. Dengan dukungan teknologi AI dan ide inovatif tim kami, ECOngkut hadir sebagai solusi yang menghubungkan masyarakat dengan jasa pengangkutan sampah profesional.

## 🎥 Demo Video

1. [Demo 1](https://drive.google.com/file/d/1myoaayN1deTTL-xxXEq9mZUBdbypondY/view?usp=drive_link)
2. [Demo 2](https://drive.google.com/file/d/14Pb2xsGVmeFus3AezJdkfgcOPoQmP_Bq/view?usp=drive_link)
3. [Demo 3](https://drive.google.com/file/d/1xnXjO0Q-ThhfWymzZ8Bu-ZpUvmiii5Ng/view?usp=drive_link)

## 🔗 Links

- **Demo Frontend**: [https://econgkut.vercel.app/](https://econgkut.vercel.app/)
- **Repository Frontend**: [https://github.com/aliakbar061/econgkut](https://github.com/aliakbar061/econgkut)
- **Repository Backend**: [https://github.com/aliakbar061/backend-econgkut](https://github.com/aliakbar061/backend-econgkut)

## 🛠️ Tech Stack

- FastAPI - Modern Python web framework
- Motor - Async MongoDB driver
- MongoDB - NoSQL database
- Google Auth - OAuth 2.0
- JWT - Authentication
- Bcrypt - Password hashing
- Uvicorn - ASGI server

## 📋 Prerequisites

- Python 3.9+
- MongoDB (local atau Atlas)
- pip

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/aliakbar061/backend-econgkut.git
cd backend-econgkut

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Environment Variables

Buat file `.env`:

```env
MONGO_URL=mongodb://localhost:27017/econgkut
DB_NAME=econgkut
CORS_ORIGINS=http://localhost:3000,https://econgkut.vercel.app
GOOGLE_CLIENT_ID=your_google_client_id_here
```

**Untuk MongoDB Atlas**, gunakan format:
```env
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net/econgkut
```

**Untuk mendapatkan Google Client ID:**
1. Buka [Google Cloud Console](https://console.cloud.google.com/)
2. Buat OAuth 2.0 Client ID
3. Tambahkan authorized origins: `http://localhost:3000`, `https://econgkut.vercel.app`

### 4. Run Server

```bash
python server.py
```

Server akan berjalan di:
- API: [http://localhost:8000](http://localhost:8000)
- Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## 📁 Project Structure

```
backend-econgkut/
├── .env                 # Environment variables (jangan commit!)
├── requirements.txt     # Python dependencies
└── server.py           # Main application
```

## 🔌 Main API Endpoints

```
GET    /                     # Root
GET    /health               # Health check
POST   /api/auth/google      # Login with Google
POST   /api/auth/register    # Register
POST   /api/auth/login       # Login
GET    /api/users            # Get all users
POST   /api/orders           # Create order
GET    /api/orders           # Get all orders
```

Dokumentasi lengkap: [http://localhost:8000/docs](http://localhost:8000/docs)

## 🧪 Testing

Gunakan Swagger UI untuk testing:
```
http://localhost:8000/docs
```

Atau dengan curl:
```bash
curl http://localhost:8000/health
```

## 🌐 Deployment

### Railway
```bash
railway login
railway init
railway up
```

### Render
1. Connect GitHub repository
2. Build: `pip install -r requirements.txt`
3. Start: `uvicorn server:app --host 0.0.0.0 --port $PORT`

### Heroku
```bash
heroku create econgkut-backend
git push heroku main
heroku config:set MONGO_URL=xxx GOOGLE_CLIENT_ID=xxx JWT_SECRET=xxx
```

## 🐛 Troubleshooting

**MongoDB connection error:**
```bash
# Cek MongoDB berjalan
# Windows: net start MongoDB
# Linux: sudo systemctl status mongod
```

**Port sudah digunakan:**
```bash
uvicorn server:app --port 5000
```

**Module not found:**
```bash
pip install -r requirements.txt
```

## 📞 Contact

GitHub Issues: [backend-econgkut/issues](https://github.com/aliakbar061/backend-econgkut/issues)

---

<div align="center">
  Dibuat dengan ❤️ oleh Tim Viro3
</div>
