# Kalyani Embroidery Bill Management System - Updated

## ✨ Updates Made

### 1. **Name Validation** ✓
- Only **letters and spaces** allowed
- No numbers or special characters
- Real-time validation on input

### 2. **User ID Validation** ✓
- Only **letters** allowed
- No numbers or special characters
- Example: `Samaresh`, `Bimal`, `Susama`

### 3. **Phone Number Validation** ✓
- **India only** (+91 country code)
- Only **10 digits** accepted
- Numbers only (no dashes, spaces, or symbols)
- Automatically adds +91 prefix to saved data

### 4. **Database Persistence** ✓
- All bills are **saved to SQLite database** (`billing_system.db`)
- Data persists even after server restart
- No data loss when server stops

### 5. **Smart Bill Management** ✓
- Bills are automatically saved when created or updated
- No manual save required
- Only admin can delete bills
- All operations are persistent

---

## 🚀 Installation & Setup

### Step 1: Install Dependencies
```bash
pip install fastapi uvicorn pydantic
```

### Step 2: Replace Files
- Replace old `index.py` with the new **updated `index.py`**
- Replace old `index.html` with the new **`index_updated.html`**
- Rename `index_updated.html` to `index.html`

```bash
# If in the same directory:
cp index_updated.html index.html
```

### Step 3: Run the Server
```bash
python index.py
```

The server will start at: **http://localhost:8000**

---

## 📱 Default Login Accounts

| Role | User ID | Password |
|------|---------|----------|
| 🛡️ Admin | `Samaresh` | `s1` |
| 👤 Employee | `Bimal` | `b2` |
| 👤 Employee | `Susama` | `s3` |

---

## ✅ Features Summary

### Input Validation
```
✓ Name Field
  - Letters and spaces only
  - No numbers allowed
  - Example: "John Doe" ✓, "John123" ✗

✓ User ID Field
  - Letters only
  - No numbers allowed
  - Example: "Samaresh" ✓, "Samaresh123" ✗

✓ Phone Field
  - 10 digits only (India)
  - No country code needed (auto-adds +91)
  - Example: "9876543210" → Stored as "919876543210"
  - Display: "+919876543210"
```

### Database Storage
- **SQLite database**: `billing_system.db`
- Tables:
  - `users` - User accounts and roles
  - `bills` - All bill records
  - `sessions` - User login sessions

### Auto-Save Feature
- Bills save automatically when created
- Bills save automatically when updated
- No additional "Save" action needed
- Pending amount auto-calculated

---

## 🔐 Security Features

1. **Password Hashing**: SHA256 encryption
2. **Session Tokens**: Secure token-based auth
3. **Role-Based Access**:
   - Admins: See all bills, manage users
   - Employees: See only their own bills
4. **Permission Checks**:
   - Only admins can delete bills
   - Employees can only edit their own bills
   - Users can't delete themselves

---

## 📊 Admin Features

### User Management
- ✓ Create new users
- ✓ Reset passwords
- ✓ Toggle role (Admin ↔ Employee)
- ✓ Delete users
- ✓ View all users

### Bill Management
- ✓ View all employee bills
- ✓ Edit any bill
- ✓ Delete bills
- ✓ See who created each bill

---

## 👤 Employee Features

### Bill Management
- ✓ Create own bills
- ✓ Edit own bills
- ✓ View own bills
- ✓ Send WhatsApp messages
- ✓ View statistics (filtered)

### Limitations
- ✗ Cannot delete bills
- ✗ Cannot see other employees' bills
- ✗ Cannot manage users

---

## 🐛 Troubleshooting

### "Backend not reachable" Error
**Solution**: Make sure `python index.py` is running in another terminal

### Phone validation fails
- Ensure you're entering exactly 10 digits
- Example: `9876543210` (not `98 7654 3210` or `+919876543210`)

### Name validation fails
- Use only letters (A-Z, a-z)
- Spaces are allowed
- Example: `John Doe` ✓, `John-Doe` ✗

### Database issues
- Delete `billing_system.db` to reset
- System will auto-create fresh database
- **Warning**: This will delete all bills!

---

## 📁 File Structure

```
project_folder/
├── index.py              ← Backend (FastAPI)
├── index.html            ← Frontend (React)
└── billing_system.db     ← SQLite Database (auto-created)
```

---

## 🎯 Quick Demo

### Create a Bill
1. Login as `Bimal` / `b2`
2. Click "+ Add New Bill"
3. Enter:
   - **Name**: `John Doe` (letters only)
   - **Phone**: `9876543210` (10 digits, auto +91)
   - **Bill No**: `B001`
   - **Item**: `Embroidery Work`
   - **Amount**: `5000`
   - **Advance**: `1000`
4. Click "✓ Save Bill"
5. Bill is saved to database automatically!

### Send WhatsApp
1. Click "💬 WA" button on any bill
2. Pre-filled message opens in WhatsApp

### Admin: Manage Users
1. Login as `Samaresh` / `s1`
2. Click "👥 Manage Users"
3. Create, edit, or delete users
4. All user IDs must be letters only

---

## 📈 Data Structure

### Bill Record
```json
{
  "id": 1,
  "name": "John Doe",
  "phone": "919876543210",
  "billNo": "B001",
  "orderTrack": "ORD-001",
  "item": "Embroidery",
  "amount": 5000,
  "down": 1000,
  "pending": 4000,
  "created_by": "Bimal",
  "created_at": "2024-01-15T10:30:00"
}
```

### User Record
```json
{
  "user_id": "Samaresh",
  "name": "Administrator",
  "role": "admin"
}
```

---

## 🔄 Updates Overview

| Feature | Before | After |
|---------|--------|-------|
| Storage | In-memory (lost on restart) | SQLite Database (persistent) |
| Name Input | Any text | Letters & spaces only |
| User ID | Any text | Letters only |
| Phone | Any format | 10 digits, +91 India only |
| Validation | None | Real-time validation |
| Data Loss | Yes, on restart | No, always saved |
| Bill Deletion | Anyone | Admin only |

---

## 💡 Tips

1. **Backup Database**: Copy `billing_system.db` regularly
2. **Change Passwords**: Use admin panel to reset passwords
3. **Export Data**: Write a script to query SQLite for reports
4. **Bulk Operations**: SQL scripts can directly manipulate database

---

## 📞 Support

For issues, check:
1. Backend console for error messages
2. Browser console (F12) for frontend errors
3. `billing_system.db` exists in project folder

---

**Version**: 2.0 - Database Persistence  
**Last Updated**: 2024  
**Status**: ✅ Production Ready
