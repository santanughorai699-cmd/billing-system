# 🧾 Better Bill System

A complete billing management system with FastAPI backend and React frontend. Admin can manage users and see all bills, while employees can only manage their own bills.

## 📦 Features

✅ **User Management** (Admin only)
- Create, update, delete users
- Reset passwords
- Toggle user roles (Admin/Employee)

✅ **Bill Management**
- Create, edit, update bills
- Search bills by name, bill number, or phone
- View bill details (total, advance, pending)
- Send WhatsApp messages to customers
- Admin sees all bills; employees see only their own

✅ **Authentication**
- Session-based login/logout
- Bearer token authentication
- Protected endpoints

✅ **UI/UX**
- Responsive dark/light theme
- Beautiful Tailwind CSS styling
- Real-time search and filtering
- Statistics dashboard

---

## 🚀 Quick Start

### 1. **Install Dependencies**

```bash
pip install -r requirements.txt
```

### 2. **Run the Server**

```bash
python index.py
```

The app will start at: **http://localhost:8000**

### 3. **Login**

Use one of the default accounts:

| User ID | Password | Role |
|---------|----------|------|
| admin | admin123 | 🛡️ Admin |
| ravi | ravi@123 | 👤 Employee |
| priya | priya@123 | 👤 Employee |
| amit | amit@123 | 👤 Employee |

---

## 📂 Project Structure

```
.
├── index.py           # FastAPI backend server
├── index.html         # React frontend (embedded)
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

---

## 🔑 Key Credentials

### Admin Account
- **User ID:** `admin`
- **Password:** `admin123`
- **Access:** Can manage users, see all bills, delete bills

### Employee Accounts
- **ravi** / `ravi@123`
- **priya** / `priya@123`
- **amit** / `amit@123`
- **Access:** Can create/edit their own bills only

---

## 🎯 Admin Features

1. **👥 Manage Users**
   - Create new users (admin or employee)
   - Reset user passwords
   - Promote/demote users
   - Delete users

2. **📊 Dashboard**
   - See all bills from all employees
   - Filter/search bills
   - Edit or delete any bill
   - View created_by column

3. **📱 Communication**
   - Send WhatsApp messages to customers with bill details

---

## 👤 Employee Features

1. **📋 Manage Bills**
   - Create new bills
   - Edit own bills only
   - Cannot delete bills (admin only)

2. **📊 Dashboard**
   - See only their own bills
   - Search and filter
   - View statistics

3. **📱 Communication**
   - Send WhatsApp messages to customers

---

## 🔒 Security Features

- Passwords hashed with SHA-256
- Bearer token-based session management
- Role-based access control (RBAC)
- CORS enabled for cross-origin requests
- Protected endpoints with dependency injection

---

## 📝 API Endpoints

### Authentication
```
POST   /api/login              # Login
POST   /api/logout             # Logout
GET    /api/me                 # Current user info
```

### Bills
```
GET    /api/bills              # List bills (role-based)
POST   /api/bills              # Create bill
PUT    /api/bills/{id}         # Update bill
DELETE /api/bills/{id}         # Delete bill (admin only)
```

### Users (Admin Only)
```
GET    /api/users              # List all users
POST   /api/users              # Create user
PUT    /api/users/{id}         # Update user role
PUT    /api/users/{id}/password # Reset password
DELETE /api/users/{id}         # Delete user
```

### Utility
```
GET    /api/health             # Health check
GET    /                       # Serve frontend
```

---

## 🎨 Customization

### Change Default Port
Edit `index.py` (last line):
```python
if __name__ == "__main__":
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)  # Change 8000
```

### Add More Demo Bills
Edit `bills_db` in `index.py`:
```python
bills_db = [
    {"id": 1, "name": "...", ...},
    # Add more bills here
]
```

### Change Colors/Theme
The frontend uses Tailwind CSS. Edit the color classes in `index.html`:
- `bg-blue-600` → `bg-green-600`
- `text-red-600` → `text-orange-600`

---

## 🛠️ Troubleshooting

**Q: Port 8000 already in use?**
```bash
# Change port in index.py or kill the process
lsof -i :8000
kill -9 <PID>
```

**Q: Backend not connecting?**
- Ensure server is running: `python index.py`
- Check browser console for errors (F12)
- Verify no CORS issues

**Q: Lost session?**
- Clear localStorage: Open DevTools → Application → Clear All

**Q: Can't send WhatsApp?**
- Ensure phone numbers include country code (e.g., +91 for India)
- WhatsApp must be installed on the device

---

## 📦 Requirements

- **Python:** 3.8+
- **FastAPI:** Web framework
- **Uvicorn:** ASGI server
- **Pydantic:** Data validation
- **React 18:** Frontend (via CDN)
- **Tailwind CSS:** Styling (via CDN)

---

## 🎓 Learning Resources

- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [React Hooks Guide](https://react.dev/reference/react)
- [Tailwind CSS](https://tailwindcss.com/)

---

## 📝 License

This project is open source and available for educational purposes.

---

## 💬 Support

If you encounter any issues:
1. Check the error message in browser console
2. Verify all dependencies are installed
3. Ensure the server is running on port 8000
4. Try clearing browser cache and localStorage

---

**Happy billing! 🧾**
