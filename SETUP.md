# Setup Guide - Kalyani Embroidery Bill System

## 📦 What is requirements.txt?

`requirements.txt` is a file that lists all Python packages needed to run this project. It makes installation easy and consistent across different computers.

---

## 🚀 Installation Steps

### Step 1: Extract Files
Extract all files to a folder:
```
project_folder/
├── index.py
├── index.html
├── requirements.txt
└── .gitignore
```

### Step 2: Open Terminal/Command Prompt
Navigate to the project folder:
```bash
cd path/to/project_folder
```

### Step 3: Install Dependencies (Recommended Way)
```bash
pip install -r requirements.txt
```

**What this does:**
- Reads the `requirements.txt` file
- Installs all listed packages automatically
- Installs exact versions specified

### Step 4: Run the Server
```bash
python index.py
```

**Output:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### Step 5: Open in Browser
Visit: **http://localhost:8000**

---

## 📋 What's in requirements.txt?

```
fastapi==0.104.1              # Web framework
uvicorn[standard]==0.24.0     # ASGI server
pydantic==2.5.0               # Data validation
python-multipart==0.0.6       # Form data parsing
```

### Why these packages?

| Package | Purpose |
|---------|---------|
| **fastapi** | Creates the API endpoints |
| **uvicorn** | Runs the web server |
| **pydantic** | Validates input data |
| **python-multipart** | Handles file uploads (if needed) |

---

## ✅ Verify Installation

### Check if Python is installed
```bash
python --version
# Should output: Python 3.8+
```

### Check if pip is installed
```bash
pip --version
# Should output: pip 21.0+
```

### After running `pip install -r requirements.txt`
```bash
pip list
```

**Should show:**
```
fastapi           0.104.1
pydantic          2.5.0
uvicorn           0.24.0
```

---

## 🐛 Troubleshooting

### ❌ "pip not found"
**Solution:** 
```bash
# Windows
python -m pip install -r requirements.txt

# Mac/Linux
python3 -m pip install -r requirements.txt
```

### ❌ "No module named fastapi"
**Solution:** Re-run installation
```bash
pip install -r requirements.txt
```

### ❌ "Address already in use"
**Solution:** Server already running on port 8000
```bash
# Windows - Kill the process
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Mac/Linux - Kill the process
lsof -ti:8000 | xargs kill -9
```

### ❌ "ModuleNotFoundError"
**Solution:** Install in correct directory
```bash
# Make sure you're in the project folder
cd /path/to/project
pip install -r requirements.txt
```

---

## 🔧 Virtual Environment (Optional but Recommended)

Using a virtual environment keeps project packages isolated.

### Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### Install from requirements.txt
```bash
pip install -r requirements.txt
```

### Run Server
```bash
python index.py
```

### Exit Virtual Environment
```bash
# Windows & Mac/Linux
deactivate
```

---

## 📝 Creating requirements.txt (For Reference)

If you need to create `requirements.txt` again:

```bash
# Install packages manually
pip install fastapi uvicorn pydantic

# Create requirements.txt with exact versions
pip freeze > requirements.txt
```

---

## 🎯 Quick Commands Cheat Sheet

```bash
# Install all dependencies
pip install -r requirements.txt

# Check installed packages
pip list

# Run the server
python index.py

# Access in browser
http://localhost:8000

# Stop server
Ctrl + C
```

---

## 📊 Python Version Support

- ✅ Python 3.8+
- ✅ Python 3.9+
- ✅ Python 3.10+
- ✅ Python 3.11+
- ✅ Python 3.12+

**Check your version:**
```bash
python --version
```

---

## 🔐 Security Notes

1. **Never share** database file (`billing_system.db`)
2. **Keep** `requirements.txt` in version control (Git)
3. **Don't keep** `.env` files if using sensitive data
4. **Use** `.gitignore` to exclude database files

---

## 📦 Updating Packages

### Update all packages
```bash
pip install -r requirements.txt --upgrade
```

### Update specific package
```bash
pip install fastapi --upgrade
```

### Save new versions
```bash
pip freeze > requirements.txt
```

---

## 🚀 Production Deployment

For production servers, create a `requirements-prod.txt`:

```bash
# Add production-specific packages
pip install gunicorn
echo "gunicorn==21.2.0" >> requirements-prod.txt
```

Run with:
```bash
gunicorn -w 4 -b 0.0.0.0:8000 index:app
```

---

## 📞 Still Having Issues?

1. **Check Python version** → `python --version`
2. **Reinstall packages** → `pip install -r requirements.txt --force-reinstall`
3. **Clear pip cache** → `pip cache purge`
4. **Try virtual environment** → See Virtual Environment section above

---

**Status**: ✅ Ready to use!  
**Last Updated**: 2024
